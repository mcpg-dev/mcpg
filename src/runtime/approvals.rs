//! Tool-gate human approval state machine.
//!
//! When a `tool_gate` plugin returns `GateDecision::PendingApproval`,
//! the runtime calls [`ApprovalRegistry::register`] to store an
//! entry keyed by `approval_id` with a `oneshot::Sender` that the
//! waiting request handler awaits. Resolution arrives from one of
//! three paths:
//!
//! 1. **Direct webhook** — `POST /webhooks/approvals/<approval_id>`
//!    with HMAC-signed `expires` + `sig` query params, body
//!    carrying an `ApprovalOutcome` JSON.
//! 2. **Notifier callback** — the notifier plugin's own
//!    `http_route` (e.g. Slack interactive callback) processes the
//!    button press, validates the payload, and calls
//!    [`ApprovalRegistry::resolve`] directly.
//! 3. **Cluster broadcast** — when an approval registered on
//!    instance A is resolved by a webhook hitting instance B, B
//!    publishes the `ApprovalResolutionEvent` on the
//!    `mcpg.approvals.resolution` cluster topic. Every instance
//!    (including A) receives + tries to resolve locally; only the
//!    holder finds the entry.
//!
//! Expiry is enforced on both ends: the request handler awaits the
//! oneshot with a deadline timer, and a periodic GC task drops
//! stale entries from the DashMap.
//!
//! # Side-effect contract
//!
//! `register` is non-blocking — it stores state and returns. The
//! caller awaits the oneshot. `resolve` is also non-blocking; it
//! sends to the oneshot and removes the entry.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use dashmap::DashMap;
use mcpg_cluster_api::ClusterBackend;
use mcpg_plugin_protocol::approval_notifier::ApprovalOutcome;
use mcpg_plugin_protocol::types::PluginIdentity;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

/// Cluster topic used to broadcast approval resolutions across
/// instances. Every gateway instance subscribes; resolutions
/// generated locally (webhook, notifier callback) publish here so
/// the holder of the pending entry — possibly a different
/// instance — can wake the request handler.
pub const APPROVAL_RESOLUTION_TOPIC: &str = "mcpg.approvals.resolution";

/// Durable backstop. KV key prefix under which resolutions are
/// mirrored so an instance that reconnects / restarts (and thus missed
/// the at-most-once `APPROVAL_RESOLUTION_TOPIC` broadcast) still wakes
/// any locally-held pending oneshot via the drain loop.
const RESOLUTION_PENDING_PREFIX: &str = "mcpg.approvals.pending.";
/// How long a mirrored resolution lingers in KV. A resolution is
/// terminal, so this only needs to cover the worst-case reconnect gap +
/// a brief restart; after it expires every live instance will already
/// have applied (or never held) the approval.
const RESOLUTION_PENDING_TTL: Duration = Duration::from_secs(120);
/// Re-drain cadence for the resolution backstop (matches the redis
/// reconnect window). The live topic is primary; this only recovers
/// losses, so a coarse interval keeps overhead negligible.
const RESOLUTION_REDRAIN_INTERVAL: Duration = Duration::from_secs(5);
/// Cap on resolutions pulled per drain pass.
const RESOLUTION_DRAIN_LIMIT: usize = 1024;

/// Default grace beyond an approval's deadline during which late
/// callbacks are still accepted. Caller-tunable.
pub const DEFAULT_CALLBACK_GRACE: Duration = Duration::from_secs(60);

/// Default GC sweep interval — how often the registry drops
/// expired entries even if no callback ever arrives.
pub const DEFAULT_EXPIRY_GC_INTERVAL: Duration = Duration::from_secs(30);

/// Errors `resolve` returns. Callers (the webhook handler, the
/// cluster subscriber) treat these as non-fatal — a missing
/// approval id usually just means a different instance holds the
/// pending request.
#[derive(Debug, Clone)]
pub enum ResolveError {
    NotFound(String),
    AlreadyResolved(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "no pending approval with id '{id}'"),
            Self::AlreadyResolved(id) => write!(f, "approval '{id}' already resolved"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Errors `verify_signature` returns. Always treated as auth
/// failures — the webhook returns 401.
#[derive(Debug, Clone)]
pub enum VerifyError {
    Malformed(String),
    Mismatch,
    Expired { expires: u64, now: u64 },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed signature: {reason}"),
            Self::Mismatch => write!(f, "signature mismatch"),
            Self::Expired { expires, now } => {
                write!(f, "expires={expires} is in the past (now={now})")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Cluster-wire representation of an approval resolution. Sent on
/// `APPROVAL_RESOLUTION_TOPIC`. Receivers attempt to resolve their
/// local registry — no-op if the entry isn't held here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolutionEvent {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    /// Node id that observed the resolution. Used for
    /// observability + self-publish dedup if a backend doesn't
    /// suppress own-messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_by: Option<String>,
}

struct PendingEntry {
    request_id: String,
    tool_name: String,
    identity: PluginIdentity,
    summary: String,
    deadline: Instant,
    deadline_at_iso: String,
    resolver: oneshot::Sender<ApprovalOutcome>,
}

/// Process-local registry of in-flight approvals. Cluster-aware
/// when constructed with a `ClusterBackend` — see
/// [`Self::start_cluster_subscriber`].
pub struct ApprovalRegistry {
    pending: DashMap<String, PendingEntry>,
    signing_key: Vec<u8>,
    callback_base_url: String,
    callback_grace: Duration,
    cluster: Option<Arc<dyn ClusterBackend>>,
    node_id: String,
    /// Durable backstop — the coordinator's KV (when it exposes
    /// one). Resolutions are mirrored here so a reconnecting / restarting
    /// instance recovers ones lost on the at-most-once topic.
    backstop_kv: Option<Arc<dyn mcpg_cluster_api::KeyValueStore>>,
    /// The resolution topic, wrapped in the same state cipher and tenant
    /// prefix as the backstop KV and as the delivery/cancellation buses.
    /// This message completes a human-approval gate, so an unsealed topic
    /// would let anything with publish rights on the shared broker approve
    /// a call the operator required a person to sign off.
    resolution_bus: Option<Arc<dyn mcpg_cluster_api::PubSub>>,
}

impl ApprovalRegistry {
    /// Build a new registry. `signing_key` must be at least 32
    /// bytes; callers SHOULD load it from a per-deploy secret
    /// (e.g. `APPROVAL_SIGNING_KEY` env). `callback_base_url`
    /// is the externally-resolvable base for webhook URLs the
    /// gateway hands to notifiers (e.g.
    /// `"https://gw.example.com"`); the registry appends
    /// `/webhooks/approvals/<id>?expires=...&sig=...`.
    pub fn new(signing_key: Vec<u8>, callback_base_url: String, callback_grace: Duration) -> Self {
        Self {
            pending: DashMap::new(),
            signing_key,
            callback_base_url,
            callback_grace,
            cluster: None,
            node_id: String::new(),
            backstop_kv: None,
            resolution_bus: None,
        }
    }

    /// Attach a cluster coordinator + node id. After this, the
    /// registry publishes resolutions on the cluster topic and
    /// (via [`Self::start_cluster_subscriber`]) acts on remote
    /// resolutions.
    pub fn with_cluster(
        mut self,
        cluster: Arc<dyn ClusterBackend>,
        node_id: String,
        // Opt-in cluster state cipher. When set, the backstop KV is
        // wrapped so mirrored approval resolutions are sealed at rest like
        // every other capability store.
        state_cipher: Option<Arc<mcpg_plugin_host::credential_cache_cipher::EventCipher>>,
        // When true, the backstop tolerates plaintext (non-envelope) reads
        // during a key-rollout migration window; default false (fail closed).
        allow_plaintext_reads: bool,
        // Opt-in per-deployment tenant segment; prefixes the backstop
        // keys (outermost, after the cipher) for broker-ACL fencing.
        tenant_segment: Option<String>,
    ) -> Self {
        // Adopt the coordinator's KV (when it exposes one) as the
        // durable resolution backstop. consul/etcd expose no KV → no
        // backstop (the at-most-once topic is all they offer).
        self.backstop_kv = cluster.key_value_store().map(|kv| {
            // Cipher INNER, tenant prefix OUTER — mirrors the
            // capability-store wrap order so the cipher AAD binds the
            // full tenant-prefixed key.
            let kv = match &state_cipher {
                Some(c) => Arc::new(
                    mcpg_plugin_host::cluster_encryption::EncryptingKeyValueStore::new(
                        kv,
                        c.clone(),
                    )
                    .allow_plaintext_reads(allow_plaintext_reads),
                ) as Arc<dyn mcpg_cluster_api::KeyValueStore>,
                None => kv,
            };
            match &tenant_segment {
                Some(seg) => Arc::new(
                    mcpg_plugin_host::cluster_tenant::TenantPrefixKeyValueStore::new(kv, seg),
                ) as Arc<dyn mcpg_cluster_api::KeyValueStore>,
                None => kv,
            }
        });
        // Same wrap order as the backstop KV above and as the sibling
        // delivery/cancellation buses: cipher inner, tenant prefix outer, so
        // the AEAD binds the full tenant-prefixed topic.
        self.resolution_bus = cluster.pub_sub().map(|bus| {
            let bus = match &state_cipher {
                Some(c) => Arc::new(
                    mcpg_plugin_host::cluster_encryption::EncryptingPubSub::new(bus, c.clone())
                        .allow_plaintext_reads(allow_plaintext_reads),
                ) as Arc<dyn mcpg_cluster_api::PubSub>,
                None => bus,
            };
            match &tenant_segment {
                Some(seg) => Arc::new(mcpg_plugin_host::cluster_tenant::TenantPrefixPubSub::new(
                    bus, seg,
                )) as Arc<dyn mcpg_cluster_api::PubSub>,
                None => bus,
            }
        });
        self.cluster = Some(cluster);
        self.node_id = node_id;
        self
    }

    /// How many approvals are currently pending. Used by admin /
    /// observability surfaces.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Register a pending approval. Returns the chosen
    /// `approval_id`, an HMAC-signed `direct_callback_url`, and
    /// the `oneshot::Receiver` the caller awaits to learn the
    /// outcome. The `approval_id` is generated server-side; the
    /// caller-supplied id (from the tool_gate's `PendingApproval`)
    /// is preserved when non-empty so the gate can pre-mint ids
    /// for tracing / replay.
    pub fn register(
        &self,
        suggested_id: &str,
        request_id: String,
        tool_name: String,
        identity: PluginIdentity,
        summary: String,
        deadline_at_iso: String,
    ) -> (String, String, oneshot::Receiver<ApprovalOutcome>) {
        let approval_id = if suggested_id.is_empty() {
            format!("appr_{}", uuid::Uuid::new_v4().simple())
        } else {
            suggested_id.to_owned()
        };
        let now = Instant::now();
        let deadline_at = parse_iso_to_instant(&deadline_at_iso, now);
        let (tx, rx) = oneshot::channel();
        let entry = PendingEntry {
            request_id,
            tool_name,
            identity,
            summary,
            deadline: deadline_at,
            deadline_at_iso: deadline_at_iso.clone(),
            resolver: tx,
        };
        // expires for the HMAC URL = deadline + grace, so late
        // legitimate callbacks (network blip after the human
        // clicked) still authenticate. Once expires is past the
        // gateway rejects the URL — but the registry's own
        // deadline timer (in await_pending) already returned
        // Denied at this point, so this is just defence-in-depth.
        let deadline_unix = deadline_at_iso_to_unix(&deadline_at_iso);
        let expires = deadline_unix.saturating_add(self.callback_grace.as_secs());
        let url = self.build_callback_url(&approval_id, expires);
        self.pending.insert(approval_id.clone(), entry);
        metrics::gauge!("mcpg_approvals_pending",).set(self.pending.len() as f64);
        metrics::counter!("mcpg_approvals_registered_total",).increment(1);
        (approval_id, url, rx)
    }

    /// Resolve a pending approval. Sends the outcome to the
    /// waiting request handler (via the stored oneshot) and
    /// removes the entry. Optionally publishes the resolution to
    /// the cluster topic when `propagate` is true — webhook +
    /// notifier-callback paths set this; the cluster subscriber
    /// path (which received the message _from_ the cluster) sets
    /// it to false to avoid republish loops.
    pub async fn resolve(
        &self,
        approval_id: &str,
        outcome: ApprovalOutcome,
        propagate: bool,
    ) -> Result<(), ResolveError> {
        let removed = self.pending.remove(approval_id);
        match removed {
            Some((_, entry)) => {
                metrics::gauge!("mcpg_approvals_pending",).set(self.pending.len() as f64);
                let outcome_label = match outcome {
                    ApprovalOutcome::Approved { .. } => "approved",
                    ApprovalOutcome::Denied { .. } => "denied",
                };
                metrics::counter!(
                    "mcpg_approvals_resolved_total",
                    "outcome" => outcome_label,
                )
                .increment(1);
                info!(
                    approval_id,
                    request_id = %entry.request_id,
                    tool_name = %entry.tool_name,
                    subject_id = entry.identity.subject_id.as_deref().unwrap_or("-"),
                    summary = %entry.summary,
                    outcome = outcome_label,
                    "approval resolved"
                );
                let send_outcome = outcome.clone();
                // Best-effort send — receiver may have dropped if
                // the request handler already timed out on its
                // deadline. That's fine: the handler returns
                // Denied/Expired on its end; the cluster broadcast
                // still goes out below.
                let _ = entry.resolver.send(send_outcome);
                if propagate {
                    self.publish_resolution(approval_id, outcome).await;
                }
                Ok(())
            }
            None => {
                debug!(
                    approval_id,
                    "resolve called for unknown approval id (likely held by another instance)"
                );
                if propagate {
                    self.publish_resolution(approval_id, outcome).await;
                }
                Err(ResolveError::NotFound(approval_id.to_owned()))
            }
        }
    }

    /// Cancel a pending approval without resolving it (e.g.,
    /// shutdown, request abort). The waiting receiver gets dropped
    /// and the request handler returns its own deadline error.
    pub fn cancel(&self, approval_id: &str) -> Option<()> {
        self.pending.remove(approval_id).map(|_| ())
    }

    /// Build the HMAC-signed callback URL the notifier embeds in
    /// its UI. Format:
    ///
    /// ```text
    /// {base}/webhooks/approvals/{approval_id}?expires={expires}&sig={base64url(hmac)}
    /// ```
    #[must_use]
    pub fn build_callback_url(&self, approval_id: &str, expires: u64) -> String {
        let payload = format!("{approval_id}|{expires}");
        let mac = hmac_sha256::HMAC::mac(payload.as_bytes(), &self.signing_key);
        let sig = URL_SAFE_NO_PAD.encode(mac);
        format!(
            "{}/webhooks/approvals/{}?expires={}&sig={}",
            self.callback_base_url.trim_end_matches('/'),
            approval_id,
            expires,
            sig,
        )
    }

    /// Verify an inbound callback's signature. Constant-time
    /// comparison.
    pub fn verify_signature(
        &self,
        approval_id: &str,
        expires: u64,
        sig_b64: &str,
    ) -> Result<(), VerifyError> {
        let now = Utc::now().timestamp() as u64;
        if expires < now {
            return Err(VerifyError::Expired { expires, now });
        }
        let provided = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| VerifyError::Malformed(e.to_string()))?;
        let payload = format!("{approval_id}|{expires}");
        let expected = hmac_sha256::HMAC::mac(payload.as_bytes(), &self.signing_key);
        if provided.ct_eq(&expected).into() {
            Ok(())
        } else {
            Err(VerifyError::Mismatch)
        }
    }

    /// Spawn the cluster subscriber loop. Required when the
    /// registry is cluster-aware. Returns `Ok(())` immediately
    /// (the loop runs as a detached tokio task); errors during
    /// subscription surface synchronously. Idempotent — calling
    /// twice spawns two subscribers, callers SHOULD only invoke
    /// once at boot.
    pub async fn start_cluster_subscriber(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(bus) = self.resolution_bus.clone() else {
            return Ok(());
        };
        let stream = bus
            .subscribe(APPROVAL_RESOLUTION_TOPIC, None)
            .await
            .map_err(|e| {
                anyhow::anyhow!("subscribe to {APPROVAL_RESOLUTION_TOPIC} failed: {e:?}")
            })?;
        let registry = Arc::clone(self);
        let node_id = self.node_id.clone();
        tokio::spawn(async move {
            cluster_subscriber_loop(stream, registry, node_id).await;
        });
        // Durable-backstop drain: recover resolutions the at-most-once
        // topic dropped (reconnect gap / restart). Each pending key is
        // applied at most once per process via the `seen` set, reset to the
        // live key set each pass so TTL'd-out keys are forgotten.
        if let Some(kv) = self.backstop_kv.clone() {
            let registry = Arc::clone(self);
            let self_node_id = self.node_id.clone();
            tokio::spawn(async move {
                resolution_backstop_drain_loop(kv, registry, self_node_id).await;
            });
        }
        Ok(())
    }

    /// Spawn the periodic expiry GC loop. Drops entries past their
    /// deadline + grace so a never-resolved approval doesn't leak
    /// the DashMap entry forever.
    pub fn start_expiry_gc(self: &Arc<Self>, interval: Duration) {
        let registry = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // First tick fires immediately — skip it.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                registry.sweep_expired();
            }
        });
    }

    fn sweep_expired(&self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        for entry in self.pending.iter() {
            if entry.value().deadline <= now {
                expired.push(entry.key().clone());
            }
        }
        for id in expired {
            if let Some((_, entry)) = self.pending.remove(&id) {
                warn!(
                    approval_id = %id,
                    request_id = %entry.request_id,
                    tool_name = %entry.tool_name,
                    deadline_at = %entry.deadline_at_iso,
                    "approval expired without resolution; dropping pending entry"
                );
                metrics::counter!(
                    "mcpg_approvals_resolved_total",
                    "outcome" => "expired",
                )
                .increment(1);
                // Send a Denied outcome so the request handler
                // (still awaiting the oneshot) wakes up and
                // returns the deny path; without this it would
                // wait until its own deadline_timer expires,
                // which is the same outcome but slower.
                let _ = entry.resolver.send(ApprovalOutcome::Denied {
                    approver_subject: None,
                    reason: Some("approval deadline expired".to_owned()),
                });
            }
        }
        metrics::gauge!("mcpg_approvals_pending",).set(self.pending.len() as f64);
    }

    async fn publish_resolution(&self, approval_id: &str, outcome: ApprovalOutcome) {
        if self.cluster.is_none() {
            return;
        }
        let event = ApprovalResolutionEvent {
            approval_id: approval_id.to_owned(),
            outcome,
            published_by: if self.node_id.is_empty() {
                None
            } else {
                Some(self.node_id.clone())
            },
        };
        let payload = match serde_json::to_vec(&event) {
            Ok(b) => Bytes::from(b),
            Err(e) => {
                warn!(error = %e, "approvals: serialize resolution event failed");
                return;
            }
        };
        // Mirror to the durable backstop BEFORE the live publish so
        // an instance that subscribes between the two still recovers it via
        // drain. Best-effort — the live topic is primary, so a KV failure
        // only forfeits recovery, not the resolution itself.
        if let Some(kv) = &self.backstop_kv {
            let key = format!("{RESOLUTION_PENDING_PREFIX}{approval_id}");
            if let Err(e) = kv
                .put(&key, payload.clone(), Some(RESOLUTION_PENDING_TTL))
                .await
            {
                warn!(
                    approval_id,
                    error = %e,
                    "approvals: backstop KV put failed (W-14); relying on live topic only"
                );
            }
        }
        let Some(bus) = &self.resolution_bus else {
            return;
        };
        if let Err(e) = bus.publish(APPROVAL_RESOLUTION_TOPIC, payload).await {
            metrics::counter!("mcpg_approvals_publish_failures_total",).increment(1);
            warn!(
                approval_id,
                error = ?e,
                "approvals: cluster publish failed (peers will not learn of this resolution)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pending-approval await helper
// ---------------------------------------------------------------------------

/// Inputs the runtime hands the await helper. Mirrors the
/// `GateDecision::PendingApproval` payload plus everything the
/// notifier needs to render an actionable approval message.
pub struct AwaitContext<'a> {
    pub approval_id: String,
    pub deadline_at: String,
    pub summary: String,
    pub target_notifiers: Vec<String>,
    pub gate_metadata: Option<serde_json::Value>,
    pub request_id: String,
    pub tool_name: String,
    pub identity: PluginIdentity,
    pub arguments: Option<serde_json::Value>,
    pub registry: &'a Arc<ApprovalRegistry>,
    pub plugin_registry: &'a Arc<mcpg_plugin_host::PluginRegistry>,
}

/// What the runtime gets back. `Approved` means continue dispatch;
/// `Denied` carries the operator-visible error fields the caller
/// folds into a JSON-RPC error.
#[derive(Debug, Clone)]
pub enum AwaitOutcome {
    Approved {
        approver_subject: Option<String>,
        reason: Option<String>,
    },
    Denied {
        http_status: u16,
        code: i32,
        message: String,
    },
}

/// Register a pending approval, fan the request out to bound
/// notifiers, and await resolution. Always returns within the
/// approval's deadline (plus a small grace) — the registry's GC
/// converts no-show approvals to a Denied outcome locally.
pub async fn await_pending_approval(ctx: AwaitContext<'_>) -> AwaitOutcome {
    let (approval_id, callback_url, rx) = ctx.registry.register(
        &ctx.approval_id,
        ctx.request_id.clone(),
        ctx.tool_name.clone(),
        ctx.identity.clone(),
        ctx.summary.clone(),
        ctx.deadline_at.clone(),
    );
    // Record the approval request, bookended with the resolved/expired
    // event below so auditors can chain the full operator-decision
    // narrative for compliance replay.
    {
        let event = mcpg_plugin_host::audit_events::approval_requested_event(
            ctx.identity.clone(),
            &ctx.request_id,
            &approval_id,
            &ctx.tool_name,
            &ctx.summary,
            &ctx.deadline_at,
            &ctx.target_notifiers,
        );
        let _ = ctx.plugin_registry.emit_audit_event(&event).await;
    }
    let request = mcpg_plugin_protocol::approval_notifier::NotificationRequest {
        approval_id: approval_id.clone(),
        summary: ctx.summary.clone(),
        deadline_at: ctx.deadline_at.clone(),
        direct_callback_url: callback_url,
        identity: ctx.identity.clone(),
        tool_name: ctx.tool_name.clone(),
        arguments: ctx.arguments.clone(),
        metadata: ctx.gate_metadata.clone(),
    };
    let notifiers = ctx
        .plugin_registry
        .resolve_approval_notifiers(&ctx.target_notifiers);
    if notifiers.is_empty() {
        warn!(
            approval_id = %approval_id,
            target_count = ctx.target_notifiers.len(),
            "approval requires notification but no notifiers resolved; fail-closed deny"
        );
        ctx.registry.cancel(&approval_id);
        return AwaitOutcome::Denied {
            http_status: 503,
            code: -32099,
            message: format!(
                "tool '{}' requires human approval but no approval_notifier plugin is bound",
                ctx.tool_name,
            ),
        };
    }
    // Dispatch in parallel — every notifier observes the same
    // request. Errors are logged + counted; one failing notifier
    // doesn't block the others or fail-closed the approval (the
    // caller may still resolve via another channel).
    for notifier in &notifiers {
        let plugin_id = notifier.manifest().id.clone();
        let request = request.clone();
        let n = Arc::clone(notifier);
        tokio::spawn(async move {
            match n.notify(&request).await {
                Ok(result) => {
                    info!(
                        approval_id = %request.approval_id,
                        plugin_id = %plugin_id,
                        channel = %result.channel,
                        "approval notification dispatched"
                    );
                }
                Err(err) => {
                    warn!(
                        approval_id = %request.approval_id,
                        plugin_id = %plugin_id,
                        error = %err,
                        "approval notification dispatch failed"
                    );
                }
            }
        });
    }
    let timeout = approval_timeout_until(&ctx.deadline_at);
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(ApprovalOutcome::Approved {
            approver_subject,
            reason,
        })) => {
            // Granted bookend.
            let event = mcpg_plugin_host::audit_events::approval_resolved_event(
                ctx.identity.clone(),
                &ctx.request_id,
                &approval_id,
                &ctx.tool_name,
                true,
                approver_subject.as_deref(),
                reason.as_deref(),
            );
            let _ = ctx.plugin_registry.emit_audit_event(&event).await;
            AwaitOutcome::Approved {
                approver_subject,
                reason,
            }
        }
        Ok(Ok(ApprovalOutcome::Denied {
            approver_subject,
            reason,
        })) => {
            // Denied bookend.
            let event = mcpg_plugin_host::audit_events::approval_resolved_event(
                ctx.identity.clone(),
                &ctx.request_id,
                &approval_id,
                &ctx.tool_name,
                false,
                approver_subject.as_deref(),
                reason.as_deref(),
            );
            let _ = ctx.plugin_registry.emit_audit_event(&event).await;
            AwaitOutcome::Denied {
                http_status: 403,
                code: -32044,
                message: format!(
                    "tool '{}' denied by {}{}",
                    ctx.tool_name,
                    approver_subject.as_deref().unwrap_or("approver"),
                    reason.map(|r| format!(": {r}")).unwrap_or_default(),
                ),
            }
        }
        Ok(Err(_)) | Err(_) => {
            ctx.registry.cancel(&approval_id);
            // Expired bookend, kept distinct from denied so auditors can
            // tell "no operator decision" from "operator rejected".
            let event = mcpg_plugin_host::audit_events::approval_expired_event(
                ctx.identity.clone(),
                &ctx.request_id,
                &approval_id,
                &ctx.tool_name,
                &ctx.deadline_at,
            );
            let _ = ctx.plugin_registry.emit_audit_event(&event).await;
            AwaitOutcome::Denied {
                http_status: 408,
                code: -32099,
                message: format!(
                    "tool '{}' approval deadline elapsed without resolution",
                    ctx.tool_name,
                ),
            }
        }
    }
}

/// Compute how long to wait for resolution. Honours the
/// `deadline_at` ISO timestamp from the gate decision; falls back
/// to 10 minutes if parsing fails (defence in depth — the registry
/// GC will sweep regardless).
fn approval_timeout_until(deadline_at_iso: &str) -> Duration {
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(deadline_at_iso) else {
        return Duration::from_secs(600);
    };
    let now = Utc::now().timestamp();
    let delta = (parsed.timestamp() - now).max(1) as u64;
    Duration::from_secs(delta).saturating_add(Duration::from_secs(2))
}

async fn cluster_subscriber_loop(
    mut stream: mcpg_cluster_api::Subscription,
    registry: Arc<ApprovalRegistry>,
    self_node_id: String,
) {
    use futures::StreamExt;
    while let Some(item) = stream.next().await {
        // A sealed bus surfaces a forged or plaintext message as an error
        // rather than a payload; drop it and keep the subscription alive.
        let msg = match item {
            Ok(m) => m,
            Err(err) => {
                warn!(
                    error = ?err,
                    "approvals: rejected an unreadable resolution event (unsealed or forged)"
                );
                continue;
            }
        };
        let event: ApprovalResolutionEvent = match serde_json::from_slice(&msg.payload) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    error = %err,
                    "approvals: malformed resolution event on cluster topic"
                );
                continue;
            }
        };
        if let Some(publisher) = event.published_by.as_ref()
            && !self_node_id.is_empty()
            && publisher == &self_node_id
        {
            // Self-publish echo — already resolved locally.
            continue;
        }
        // propagate=false because we just received this event from
        // the cluster; republishing would cause an infinite loop.
        match registry
            .resolve(&event.approval_id, event.outcome, false)
            .await
        {
            Ok(()) => {
                debug!(
                    approval_id = %event.approval_id,
                    "approvals: resolved local pending entry from cluster broadcast"
                );
            }
            Err(ResolveError::NotFound(_)) => {
                // Expected — the resolution belongs to a different
                // instance.
            }
            Err(ResolveError::AlreadyResolved(_)) => {
                // Race: webhook hit two instances simultaneously.
                // First-write-wins; later events are silently
                // discarded.
            }
        }
    }
    warn!("approvals: cluster subscriber loop ended (stream closed)");
}

/// Durable-backstop drain. Periodically lists the mirrored
/// resolutions and applies each (once per process) to the local
/// registry — the recovery net for resolutions dropped by the
/// at-most-once `APPROVAL_RESOLUTION_TOPIC`. Self-published echoes are
/// skipped (already applied locally); a resolution for an approval this
/// instance doesn't hold is a harmless `NotFound`.
async fn resolution_backstop_drain_loop(
    kv: Arc<dyn mcpg_cluster_api::KeyValueStore>,
    registry: Arc<ApprovalRegistry>,
    self_node_id: String,
) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        match kv
            .list_prefix(RESOLUTION_PENDING_PREFIX, RESOLUTION_DRAIN_LIMIT)
            .await
        {
            Ok(entries) => {
                let mut current = std::collections::HashSet::with_capacity(entries.len());
                for (key, entry) in entries {
                    current.insert(key.clone());
                    if seen.contains(&key) {
                        continue;
                    }
                    let event: ApprovalResolutionEvent = match serde_json::from_slice(&entry.bytes)
                    {
                        Ok(e) => e,
                        Err(err) => {
                            warn!(error = %err, key = %key, "approvals: malformed backstop entry (W-14)");
                            continue;
                        }
                    };
                    if let Some(publisher) = event.published_by.as_ref()
                        && !self_node_id.is_empty()
                        && publisher == &self_node_id
                    {
                        // Self-publish echo — already resolved locally.
                        continue;
                    }
                    match registry
                        .resolve(&event.approval_id, event.outcome, false)
                        .await
                    {
                        Ok(()) => {
                            metrics::counter!("mcpg_approvals_backstop_recovered_total")
                                .increment(1);
                            debug!(
                                approval_id = %event.approval_id,
                                "approvals: resolved local pending entry from backstop drain (W-14)"
                            );
                        }
                        // Resolution belongs to another instance, or a race
                        // already resolved it — both expected and harmless.
                        Err(ResolveError::NotFound(_)) | Err(ResolveError::AlreadyResolved(_)) => {}
                    }
                }
                seen = current;
            }
            Err(e) => {
                warn!(error = %e, "approvals: backstop drain failed (W-14); live topic only this pass");
            }
        }
        tokio::time::sleep(RESOLUTION_REDRAIN_INTERVAL).await;
    }
}

fn parse_iso_to_instant(iso: &str, now: Instant) -> Instant {
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(iso) else {
        // Malformed ISO — caller already validated, but be
        // defensive: fall back to `now + 5min` so the entry
        // expires soon.
        return now + Duration::from_secs(300);
    };
    let unix = parsed.timestamp();
    let now_unix = Utc::now().timestamp();
    let delta = (unix - now_unix).max(0) as u64;
    now + Duration::from_secs(delta)
}

fn deadline_at_iso_to_unix(iso: &str) -> u64 {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|dt| dt.timestamp().max(0) as u64)
        .unwrap_or_else(|_| {
            // Malformed — fall back to now+1h so the URL is at
            // least usable for a short window.
            Utc.timestamp_opt(Utc::now().timestamp() + 3600, 0)
                .single()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(0)
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn key() -> Vec<u8> {
        b"0123456789abcdef0123456789abcdef".to_vec()
    }

    fn identity() -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("alice".into()),
            auth_provider: None,
            issuer: None,
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: BTreeMap::new(),
        }
    }

    fn future_iso(secs_ahead: i64) -> String {
        let dt = Utc::now() + chrono::Duration::seconds(secs_ahead);
        dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    #[tokio::test]
    async fn register_then_resolve_delivers_outcome() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let (approval_id, _url, rx) = reg.register(
            "",
            "req-1".into(),
            "rm".into(),
            identity(),
            "delete /etc".into(),
            future_iso(60),
        );
        assert_eq!(reg.pending_count(), 1);
        reg.resolve(
            &approval_id,
            ApprovalOutcome::Approved {
                approver_subject: Some("bob".into()),
                reason: None,
            },
            false,
        )
        .await
        .unwrap();
        assert_eq!(reg.pending_count(), 0);
        let outcome = rx.await.unwrap();
        match outcome {
            ApprovalOutcome::Approved {
                approver_subject, ..
            } => {
                assert_eq!(approver_subject.as_deref(), Some("bob"));
            }
            _ => panic!("expected Approved"),
        }
    }

    #[tokio::test]
    async fn backstop_drain_resolves_locally_held_pending() {
        // A resolution that this instance missed on the live topic
        // (here: never published to a bus at all, only mirrored to KV) is
        // recovered by the drain loop and wakes the locally-held oneshot.
        use crate::builtins::cluster_primitives::MemoryKv;
        use mcpg_cluster_api::KeyValueStore;

        let reg = Arc::new(ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        ));
        let (approval_id, _url, rx) = reg.register(
            "",
            "req-bs".into(),
            "rm".into(),
            identity(),
            "delete /srv".into(),
            future_iso(60),
        );

        // Mirror a resolution into KV as `publish_resolution` would, but
        // skip the live topic entirely — receipt proves the drain path.
        let kv: Arc<dyn KeyValueStore> = Arc::new(MemoryKv::new());
        let event = ApprovalResolutionEvent {
            approval_id: approval_id.clone(),
            outcome: ApprovalOutcome::Approved {
                approver_subject: Some("carol".into()),
                reason: None,
            },
            published_by: Some("peer-node".into()),
        };
        kv.put(
            &format!("{RESOLUTION_PENDING_PREFIX}{approval_id}"),
            Bytes::from(serde_json::to_vec(&event).unwrap()),
            Some(RESOLUTION_PENDING_TTL),
        )
        .await
        .unwrap();

        // This instance is "this-node" — not the publisher, so the drain
        // does not treat it as a self-echo.
        tokio::spawn(resolution_backstop_drain_loop(
            kv,
            Arc::clone(&reg),
            "this-node".to_owned(),
        ));

        let outcome =
            tokio::time::timeout(RESOLUTION_REDRAIN_INTERVAL * 2 + Duration::from_secs(1), rx)
                .await
                .expect("backstop drain should resolve within a redrain cycle")
                .expect("oneshot delivered");
        match outcome {
            ApprovalOutcome::Approved {
                approver_subject, ..
            } => assert_eq!(approver_subject.as_deref(), Some("carol")),
            _ => panic!("expected Approved"),
        }
        assert_eq!(reg.pending_count(), 0);
    }

    #[tokio::test]
    async fn backstop_drain_skips_self_published_echo() {
        // A resolution this node itself published must NOT be
        // re-applied from the backstop (it was already resolved locally).
        use crate::builtins::cluster_primitives::MemoryKv;
        use mcpg_cluster_api::KeyValueStore;

        let reg = Arc::new(ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        ));
        let (approval_id, _url, rx) = reg.register(
            "",
            "req-echo".into(),
            "rm".into(),
            identity(),
            "delete /var".into(),
            future_iso(60),
        );

        let kv: Arc<dyn KeyValueStore> = Arc::new(MemoryKv::new());
        let event = ApprovalResolutionEvent {
            approval_id: approval_id.clone(),
            outcome: ApprovalOutcome::Approved {
                approver_subject: Some("self".into()),
                reason: None,
            },
            published_by: Some("this-node".into()),
        };
        kv.put(
            &format!("{RESOLUTION_PENDING_PREFIX}{approval_id}"),
            Bytes::from(serde_json::to_vec(&event).unwrap()),
            Some(RESOLUTION_PENDING_TTL),
        )
        .await
        .unwrap();

        // Same node id as the publisher → echo, must be skipped.
        tokio::spawn(resolution_backstop_drain_loop(
            kv,
            Arc::clone(&reg),
            "this-node".to_owned(),
        ));

        // The oneshot must NOT fire from the backstop within a couple cycles.
        let res =
            tokio::time::timeout(RESOLUTION_REDRAIN_INTERVAL * 2 + Duration::from_secs(1), rx)
                .await;
        assert!(
            res.is_err(),
            "self-published echo must not be re-applied from the backstop"
        );
        assert_eq!(reg.pending_count(), 1, "pending entry should remain");
    }

    #[tokio::test]
    async fn resolve_unknown_returns_not_found() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let result = reg
            .resolve(
                "nope",
                ApprovalOutcome::Denied {
                    approver_subject: None,
                    reason: None,
                },
                false,
            )
            .await;
        assert!(matches!(result, Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn callback_url_round_trips_signature() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let approval_id = "appr_123";
        let expires = (Utc::now().timestamp() + 600) as u64;
        let url = reg.build_callback_url(approval_id, expires);
        assert!(url.starts_with("https://gw.example.com/webhooks/approvals/appr_123?expires="));
        // Pull sig out of the URL.
        let sig = url.rsplit_once("sig=").unwrap().1;
        reg.verify_signature(approval_id, expires, sig).unwrap();
    }

    #[test]
    fn verify_signature_rejects_tampered_id() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let expires = (Utc::now().timestamp() + 600) as u64;
        let url = reg.build_callback_url("appr_123", expires);
        let sig = url.rsplit_once("sig=").unwrap().1;
        // Same sig, different approval_id → mismatch.
        let res = reg.verify_signature("appr_999", expires, sig);
        assert!(matches!(res, Err(VerifyError::Mismatch)));
    }

    #[test]
    fn verify_signature_rejects_expired() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let expires = (Utc::now().timestamp() - 60) as u64;
        let res = reg.verify_signature("appr_123", expires, "abc");
        assert!(matches!(res, Err(VerifyError::Expired { .. })));
    }

    #[test]
    fn verify_signature_rejects_malformed_b64() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let expires = (Utc::now().timestamp() + 600) as u64;
        let res = reg.verify_signature("appr_123", expires, "!!not_b64!!");
        assert!(matches!(res, Err(VerifyError::Malformed(_))));
    }

    #[tokio::test]
    async fn cancel_drops_pending_without_sending_outcome() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let (approval_id, _url, rx) = reg.register(
            "",
            "req-1".into(),
            "rm".into(),
            identity(),
            "x".into(),
            future_iso(60),
        );
        reg.cancel(&approval_id).unwrap();
        assert_eq!(reg.pending_count(), 0);
        // Receiver gets dropped → recv yields RecvError.
        let result = rx.await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sweep_expired_drops_past_deadline_entries() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        // Past deadline.
        let (_aid, _url, rx) = reg.register(
            "",
            "req-1".into(),
            "rm".into(),
            identity(),
            "x".into(),
            future_iso(-60),
        );
        reg.sweep_expired();
        assert_eq!(reg.pending_count(), 0);
        // Receiver gets a Denied outcome with reason "expired".
        match rx.await.unwrap() {
            ApprovalOutcome::Denied { reason, .. } => {
                assert!(reason.unwrap().contains("expired"));
            }
            _ => panic!("expected Denied"),
        }
    }

    #[tokio::test]
    async fn await_helper_denies_when_no_notifiers_bound() {
        let registry = Arc::new(ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        ));
        let plugin_registry = Arc::new(mcpg_plugin_host::PluginRegistry::new());
        let outcome = super::await_pending_approval(super::AwaitContext {
            approval_id: String::new(),
            deadline_at: future_iso(60),
            summary: "x".into(),
            target_notifiers: Vec::new(),
            gate_metadata: None,
            request_id: "req-1".into(),
            tool_name: "rm".into(),
            identity: identity(),
            arguments: None,
            registry: &registry,
            plugin_registry: &plugin_registry,
        })
        .await;
        match outcome {
            super::AwaitOutcome::Denied { http_status, .. } => {
                assert_eq!(http_status, 503);
            }
            _ => panic!("expected Denied (no notifiers configured)"),
        }
        // The cancel call inside await should leave nothing pending.
        assert_eq!(registry.pending_count(), 0);
    }

    #[tokio::test]
    async fn await_helper_resolves_when_outcome_arrives() {
        use mcpg_plugin_protocol::approval_notifier::ApprovalNotifier;
        use mcpg_plugin_protocol::async_trait;

        struct StubNotifier;
        #[async_trait]
        impl ApprovalNotifier for StubNotifier {
            fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
                static M: std::sync::OnceLock<mcpg_plugin_protocol::PluginManifest> =
                    std::sync::OnceLock::new();
                M.get_or_init(|| mcpg_plugin_protocol::PluginManifest {
                    id: "test.notify.stub".into(),
                    version: "0.1.0".into(),
                    name: "stub".into(),
                    plugin_class: mcpg_plugin_protocol::manifest::PluginClass::ApprovalNotifier,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: vec![],
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                })
            }
            async fn notify(
                &self,
                _request: &mcpg_plugin_protocol::approval_notifier::NotificationRequest,
            ) -> Result<
                mcpg_plugin_protocol::approval_notifier::NotificationResult,
                mcpg_plugin_protocol::approval_notifier::NotificationError,
            > {
                Ok(
                    mcpg_plugin_protocol::approval_notifier::NotificationResult {
                        channel: "stub".into(),
                        metadata: Default::default(),
                    },
                )
            }
        }

        let registry = Arc::new(ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        ));
        let mut plugin_registry = mcpg_plugin_host::PluginRegistry::new();
        plugin_registry
            .register_approval_notifier(
                Arc::new(StubNotifier),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .unwrap();
        let plugin_registry = Arc::new(plugin_registry);

        let approval_id = "appr_e2e";
        let registry_for_resolver = Arc::clone(&registry);
        // Resolver task — in production this comes from the
        // webhook handler.
        let resolver = tokio::spawn(async move {
            // Yield enough for the awaiter to register first.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            registry_for_resolver
                .resolve(
                    approval_id,
                    ApprovalOutcome::Approved {
                        approver_subject: Some("alice".into()),
                        reason: None,
                    },
                    false,
                )
                .await
                .unwrap();
        });
        let outcome = super::await_pending_approval(super::AwaitContext {
            approval_id: approval_id.into(),
            deadline_at: future_iso(60),
            summary: "x".into(),
            target_notifiers: Vec::new(),
            gate_metadata: None,
            request_id: "req-1".into(),
            tool_name: "rm".into(),
            identity: identity(),
            arguments: None,
            registry: &registry,
            plugin_registry: &plugin_registry,
        })
        .await;
        resolver.await.unwrap();
        match outcome {
            super::AwaitOutcome::Approved {
                approver_subject, ..
            } => {
                assert_eq!(approver_subject.as_deref(), Some("alice"));
            }
            _ => panic!("expected Approved"),
        }
    }

    #[tokio::test]
    async fn suggested_id_preserved_when_provided() {
        let reg = ApprovalRegistry::new(
            key(),
            "https://gw.example.com".into(),
            DEFAULT_CALLBACK_GRACE,
        );
        let (approval_id, _url, _rx) = reg.register(
            "appr_external_id",
            "req-1".into(),
            "rm".into(),
            identity(),
            "x".into(),
            future_iso(60),
        );
        assert_eq!(approval_id, "appr_external_id");
    }
}
