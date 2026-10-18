//! Optional Control Plane attachment — gateway side.
//!
//! When the `cp-attached` Cargo feature is enabled and operator
//! config provides a CP endpoint + enrollment URL, this module:
//!
//! 1. Starts an `AgentRunner` (Register → open Channel → heartbeat,
//!    apply ConfigUpdate, receive the org's licence) before the
//!    gateway gates its plugins, because the licence the control
//!    plane delivers is what an attached gateway gates on.
//! 2. Once the runtime exists, bridges the agent's `MetricsBuffer`
//!    into the gateway's `runtime::cp_metrics::ToolCallRecorder` slot
//!    via a small adapter, so every tool call recorded at dispatch
//!    time flows over Channel as a `MetricsReport`.
//! 3. Returns a `JoinHandle` for graceful shutdown.
//!
//! When the feature is OFF, [`start_if_configured`] is a no-op
//! that does nothing regardless of config presence — the flagship
//! `mcpg` build does not link cp-client deps.

use crate::config::AppConfig;
use crate::runtime::GatewayRuntime;

/// Handle to the optional CP-attach background work. Cloning is
/// not supported — exactly one consumer should drive shutdown.
pub struct CpAttachHandle {
    #[cfg(feature = "cp-attached")]
    agent_handle: tokio::task::JoinHandle<()>,
    /// Late-bound handle to the live `AppState`, shared with the config-apply
    /// hook so a pushed config can hot-reload the running gateway. The agent
    /// starts before `AppState` exists, so the state is bound afterwards via
    /// [`CpAttachHandle::bind_state`].
    #[cfg(feature = "cp-attached")]
    config_state: std::sync::Arc<arc_swap::ArcSwapOption<crate::app::AppState>>,
    /// The agent's handles the runtime is wired to once it exists.
    #[cfg(feature = "cp-attached")]
    runtime_hooks: attached::RuntimeHooks,
}

impl CpAttachHandle {
    /// Wire the agent's quota status and tool-call recorder into the runtime.
    /// Call before the runtime is wrapped in `Arc<ArcSwap>`.
    pub fn wire_runtime(&self, runtime: &mut GatewayRuntime) {
        #[cfg(feature = "cp-attached")]
        self.runtime_hooks.wire(runtime);
        #[cfg(not(feature = "cp-attached"))]
        let _ = runtime;
    }

    /// Cancel the agent task. Idempotent.
    ///
    /// Prefer [`shutdown_agent`] on the process teardown path: aborting drops
    /// whatever tool-call samples the agent has buffered, and those are
    /// billable.
    pub fn shutdown(self) {
        #[cfg(feature = "cp-attached")]
        self.agent_handle.abort();
    }

    /// Bind the live `AppState` so CP-pushed configs hot-reload it. No-op when
    /// the `cp-attached` feature is off. Safe to call once after `AppState` is
    /// built; the apply hook shares the same `ArcSwap` handles, so a reload
    /// through the bound state is visible to the running server.
    ///
    /// A licence or bound plugin set the control plane delivered after the
    /// boot gate ran reached hooks that had no state to reload, so the gateway
    /// is gated again here, and reloaded when that changes what it withholds.
    pub async fn bind_state(&self, state: crate::app::AppState) {
        #[cfg(feature = "cp-attached")]
        {
            self.config_state
                .store(Some(std::sync::Arc::new(state.clone())));
            if state.runtime.load().license_state().is_behind_platform() {
                regate_running(&state).await;
            }
        }
        #[cfg(not(feature = "cp-attached"))]
        let _ = state;
    }
}

/// Gate the running gateway again on the latest licence delivery and bound
/// plugin set, and reload it when the answer withholds or holds other items
/// than the running runtime: a lower licence takes away what it no longer
/// covers, a higher one gives back what was withheld, with no restart.
/// Returns whether the running gateway now runs on that answer; when not,
/// what it runs is left as it was and [`watch_running_licence`] tries again.
#[cfg(feature = "cp-attached")]
pub(crate) async fn regate_running(state: &crate::app::AppState) -> bool {
    let reached = regate_running_once(state).await;
    // Readiness and health report a regate that keeps failing as degraded.
    crate::license_gate::record_regate(reached);
    reached
}

#[cfg(feature = "cp-attached")]
async fn regate_running_once(state: &crate::app::AppState) -> bool {
    let regate = {
        let runtime = state.runtime.load_full();
        runtime.license_state().regate(&state.base_config.load())
    };
    match regate {
        Ok(false) => true,
        Ok(true) => {
            tracing::info!(
                "control_plane: the delivered licence changes what this gateway withholds; \
                 reloading"
            );
            match crate::app::reapply_config(state).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::error!(
                        error = %format!("{e:#}"),
                        "control_plane: reload for the delivered licence failed; what is \
                         running keeps running until a retry applies it"
                    );
                    false
                }
            }
        }
        Err(e) => {
            tracing::error!(
                error = %format!("{e:#}"),
                "control_plane: the licence gate refuses this gateway's config; what is running \
                 keeps running until a retry applies a config it admits"
            );
            false
        }
    }
}

/// How often a running attached gateway checks its licence against the clock
/// and the latest delivery.
#[cfg(feature = "cp-attached")]
const LICENCE_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// What [`check_running_licence`] has applied, so each lapse and each
/// delivery generation is gated until it reaches the running gateway, and
/// then once.
#[cfg(feature = "cp-attached")]
#[derive(Debug, Default)]
pub(crate) struct LicenceWatch {
    lapse: Option<i64>,
    generation: Option<u64>,
    /// Regates in a row that did not reach the running gateway.
    failures: u32,
    /// Watch ticks still to let pass before the next try.
    backoff: u32,
}

#[cfg(feature = "cp-attached")]
impl LicenceWatch {
    /// Whether to gate again on this tick: `lapse` or `generation` is one
    /// the running gateway has not been gated on, and no backoff is left.
    fn due(&mut self, lapse: Option<i64>, behind: bool, generation: u64) -> bool {
        let lapsed = lapse.is_some() && lapse != self.lapse;
        let missed = behind && self.generation != Some(generation);
        if !lapsed && !missed {
            // Caught up, by a delivery's own regate when one failed here: the
            // next lapse or delivery owes no backoff.
            self.failures = 0;
            self.backoff = 0;
            return false;
        }
        if self.backoff > 0 {
            self.backoff -= 1;
            return false;
        }
        true
    }

    fn applied(&mut self, lapse: Option<i64>, generation: u64) {
        if lapse.is_some() {
            self.lapse = lapse;
        }
        self.generation = Some(generation);
        self.failures = 0;
        self.backoff = 0;
    }

    /// Record a failed regate; returns how many watch intervals pass before
    /// the next try: 1, 2, 4, 8, then 16.
    fn failed(&mut self) -> u32 {
        self.failures = self.failures.saturating_add(1);
        let wait = 1 << (self.failures - 1).min(4);
        self.backoff = wait - 1;
        wait
    }
}

/// Gate the running gateway again when the delivered licence it loaded gated
/// items under passes the end of its grace, or when it runs behind the latest
/// delivery or bound set (a reload that read an older one finished last, or
/// the regate a delivery started failed). Neither brings a delivery that
/// would gate it, and a control plane that cannot be reached delivers nothing
/// at all. A regate that fails is tried again with backoff.
#[cfg(feature = "cp-attached")]
pub(crate) async fn check_running_licence(state: &crate::app::AppState, seen: &mut LicenceWatch) {
    let (lapse, behind) = {
        let runtime = state.runtime.load();
        let license = runtime.license_state();
        (
            license
                .lapses_at
                .filter(|t| *t <= chrono::Utc::now().timestamp()),
            license.is_behind_platform(),
        )
    };
    let generation = crate::license_gate::platform::generation();
    if !seen.due(lapse, behind, generation) {
        return;
    }
    if lapse.is_some() && lapse != seen.lapse {
        tracing::warn!(
            "control_plane: the delivered licence's grace period, or the day a restart counts \
             the licence mcpg.cloud last proved, ended; gating again"
        );
    }
    if regate_running(state).await {
        seen.applied(lapse, generation);
    } else {
        let retry_in = LICENCE_WATCH_INTERVAL * seen.failed();
        tracing::warn!(
            ?retry_in,
            failures = seen.failures,
            "control_plane: the licence did not reach the running gateway; trying again"
        );
    }
}

/// Run [`check_running_licence`] every [`LICENCE_WATCH_INTERVAL`] once the
/// gateway's state is bound.
#[cfg(feature = "cp-attached")]
async fn watch_running_licence(
    state: std::sync::Arc<arc_swap::ArcSwapOption<crate::app::AppState>>,
) {
    let mut seen = LicenceWatch::default();
    let mut ticker = tokio::time::interval(LICENCE_WATCH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Some(state) = state.load_full() {
            check_running_licence(&state, &mut seen).await;
        }
    }
}

/// The running agent's graceful-stop trigger. A gateway process attaches to at
/// most one control plane, so this is set once at boot and read by the
/// teardown path — which has no other route to it, since the attach handle is
/// built before `AppState` exists.
#[cfg(feature = "cp-attached")]
static AGENT_SHUTDOWN: std::sync::OnceLock<mcpg_control_plane_client::AgentShutdown> =
    std::sync::OnceLock::new();

/// Ask the CP agent to ship whatever it still has buffered, and wait up to
/// `timeout` for it to finish. No-op when the gateway is not CP-attached.
///
/// Buffered samples are billable tool calls, so letting the process exit
/// without this silently costs a flush interval of revenue on every deploy.
pub async fn shutdown_agent(timeout: std::time::Duration) {
    #[cfg(feature = "cp-attached")]
    {
        let Some(trigger) = AGENT_SHUTDOWN.get() else {
            return;
        };
        trigger.trigger();
        if tokio::time::timeout(timeout, trigger.finished())
            .await
            .is_err()
        {
            tracing::warn!(
                ?timeout,
                "control_plane: agent did not finish its shutdown flush in time"
            );
        }
    }
    #[cfg(not(feature = "cp-attached"))]
    let _ = timeout;
}

/// Start the Control Plane agent if config requests it, before the license
/// gate runs: the licence the control plane delivers is what an attached
/// gateway gates on. Wire the runtime with [`CpAttachHandle::wire_runtime`]
/// once it exists.
///
/// Returns `Ok(None)` when no attachment is configured (or the
/// feature is off) — the gateway runs standalone with the
/// default `NoopRecorder`.
pub async fn start_if_configured(
    config: &AppConfig,
    config_sources: &[crate::config::ConfigSource],
    observability: &crate::observability::ObservabilityHandle,
) -> anyhow::Result<Option<CpAttachHandle>> {
    #[cfg(not(feature = "cp-attached"))]
    {
        let _ = (config_sources, observability);
        // Feature off — nothing to do. A configured block is still worth one
        // line: on a managed platform the control plane renders it, and a
        // gateway that ignores it in silence looks enrolled from every side
        // but the platform's.
        if config.gateway.control_plane.is_some() {
            tracing::warn!(
                "control_plane: `gateway.control_plane` is configured but this binary was built \
                 without the `cp-attached` feature — the block is ignored and the gateway will \
                 not enrol; rebuild with `--features cp-attached`"
            );
        }
        Ok(None)
    }
    #[cfg(feature = "cp-attached")]
    {
        attached::start(config, config_sources, observability).await
    }
}

#[cfg(feature = "cp-attached")]
mod attached {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Context as _;
    use arc_swap::{ArcSwap, ArcSwapOption};
    use mcpg_control_plane_client::{
        AgentRunner, AgentRunnerConfig, DekHandle, MetricsBuffer, QuotaStatus,
        SampleOutcome as ClientOutcome, ToolCallSample as ClientSample,
    };
    use tracing::{info, warn};

    use crate::config::AppConfig;
    use crate::runtime::GatewayRuntime;
    use crate::runtime::cp_metrics::{
        SampleOutcome as GatewayOutcome, ToolCallRecorder, ToolCallSample as GatewaySample,
    };
    use crate::runtime::cp_quota::{EventsPlan, QuotaStatusInfo, QuotaStatusProvider};

    use super::CpAttachHandle;

    /// Adapter that translates the gateway-side
    /// `cp_metrics::ToolCallSample` into the cp-client wire
    /// shape and pushes into the agent's `MetricsBuffer`. The
    /// flush ticker on the `AgentRunner`'s Channel session
    /// drains the buffer every 30s into a `MetricsReport`.
    struct CpClientRecorder {
        buf: MetricsBuffer,
        /// Whether the dispatch site should capture
        /// `request_payload` + `response_payload`. True only
        /// when operator config + license both opt in.
        capture_payloads: bool,
        /// Lock-free handle to the per-tenant DEK pushed by the
        /// CP at Register / CredentialRotation. When `Some`, the
        /// recorder encrypts captured payloads at the source so
        /// the CP host never sees plaintext. When `None`,
        /// payloads are shipped plaintext and the CP wraps at
        /// ingest (legacy path, preserved for compat).
        dek: Arc<ArcSwap<Option<DekHandle>>>,
    }

    impl CpClientRecorder {
        /// Encrypt one optional payload buffer with the current
        /// DEK. Returns `(bytes, encrypted, dek_version)`. On
        /// encryption failure the bytes are *dropped* — never
        /// shipped plaintext — to keep the source-side guarantee
        /// intact. The CP will see a sample with no payload, not
        /// a leaked plaintext.
        fn encrypt_payload(
            payload: Option<Vec<u8>>,
            dek: &Option<DekHandle>,
        ) -> (Option<Vec<u8>>, bool, u32) {
            let Some(bytes) = payload else {
                return (None, false, 0);
            };
            if bytes.is_empty() {
                return (Some(bytes), false, 0);
            }
            let Some(handle) = dek.as_ref() else {
                return (Some(bytes), false, 0);
            };
            match handle.encrypt(&bytes) {
                Ok(ct) => (Some(ct), true, handle.version()),
                Err(e) => {
                    warn!(error = ?e, "cp_attach: payload encrypt failed; dropping bytes");
                    (None, false, 0)
                }
            }
        }
    }

    impl ToolCallRecorder for CpClientRecorder {
        fn record(&self, sample: GatewaySample) {
            // Snapshot the DEK once per sample so request +
            // response are stamped with the same version even if
            // a rotation lands mid-record.
            let guard = self.dek.load();
            let snapshot: Option<DekHandle> = guard.as_ref().clone();
            let (req_bytes, req_enc, req_ver) =
                Self::encrypt_payload(sample.request_payload, &snapshot);
            let (resp_bytes, resp_enc, resp_ver) =
                Self::encrypt_payload(sample.response_payload, &snapshot);
            // Both halves see the same DEK snapshot, so versions
            // agree by construction. We pick whichever side
            // actually got encrypted; if neither did, version
            // stays 0.
            let payload_encrypted = req_enc || resp_enc;
            let dek_version = if req_enc { req_ver } else { resp_ver };
            self.buf.record(ClientSample {
                plugin_id: sample.plugin_id,
                tool_name: sample.tool_name,
                binding_id: sample.binding_id,
                started_at: sample.started_at,
                duration: sample.duration,
                outcome: match sample.outcome {
                    GatewayOutcome::Ok => ClientOutcome::Ok,
                    GatewayOutcome::ClientError => ClientOutcome::ClientError,
                    GatewayOutcome::ServerError => ClientOutcome::ServerError,
                    GatewayOutcome::PolicyDenied => ClientOutcome::PolicyDenied,
                    GatewayOutcome::QuotaExceeded => ClientOutcome::QuotaExceeded,
                    // First-class on the wire now: the CP excludes
                    // this outcome from the billing rollup and the
                    // `tool_calls_per_month` quota math (a replay
                    // served a cached envelope; no new dispatch ran).
                    // The `error_code` gateway-side still carries
                    // `"idempotent_replay"` (set by
                    // `build_idempotency_replay_response`) for log
                    // correlation.
                    GatewayOutcome::IdempotentReplay => ClientOutcome::IdempotentReplay,
                },
                error_code: sample.error_code,
                error_hash: sample.error_hash,
                request_id: sample.request_id,
                caller_subject: sample.caller_subject,
                request_payload: req_bytes,
                response_payload: resp_bytes,
                payload_encrypted,
                dek_version,
            });
        }

        fn payload_capture_enabled(&self) -> bool {
            self.capture_payloads
        }

        fn record_event_usage(
            &self,
            event_name: &str,
            mode: &str,
            delivered: u64,
            abandoned: u64,
            bytes: u64,
        ) {
            self.buf.record_events(
                event_name,
                mode,
                mcpg_control_plane_client::metrics::EventCounts {
                    delivered,
                    abandoned,
                    bytes,
                    ..Default::default()
                },
            );
        }

        fn record_event_ingest(&self, event_name: &str, source: &str, ingested: u64, bytes: u64) {
            self.buf.record_events(
                event_name,
                source,
                mcpg_control_plane_client::metrics::EventCounts {
                    ingested,
                    bytes,
                    ..Default::default()
                },
            );
        }
    }

    /// Snapshot source for the agent's periodic `StatusReport` —
    /// everything it ships is state the process already tracks: the
    /// plugin registry's load table, the coordinator-health gauge cell
    /// maintained by the periodic KV probe, and the coordinator's peer
    /// cache. No new probing happens here.
    pub(super) struct GatewayStatusSource {
        /// Same late-bound cell the config-apply hook shares; until
        /// `AppState` is bound the snapshot falls back to boot config.
        pub(super) state: Arc<ArcSwapOption<crate::app::AppState>>,
        pub(super) boot_cluster_kind: String,
        pub(super) boot_single_node: bool,
        pub(super) refusal: Arc<ArcSwapOption<crate::license_gate::DeliveryRefusal>>,
    }

    /// The coordinator-health cell as a tri-state: `None` until the
    /// periodic probe has run (single_node / KV-less coordinators never
    /// probe), then whether the last KV ping was answered.
    fn cluster_backend_up() -> Option<bool> {
        use crate::runtime::{CLUSTER_BACKEND_UP, CLUSTER_UP_DOWN, CLUSTER_UP_HEALTHY};
        match CLUSTER_BACKEND_UP.load(std::sync::atomic::Ordering::Relaxed) {
            CLUSTER_UP_HEALTHY => Some(true),
            CLUSTER_UP_DOWN => Some(false),
            _ => None,
        }
    }

    #[async_trait::async_trait]
    impl mcpg_control_plane_client::StatusSource for GatewayStatusSource {
        async fn snapshot(&self) -> mcpg_control_plane_client::StatusSnapshot {
            use mcpg_control_plane_client::{
                ClusterStatusSample, DeliveryRefusalSample, PluginStatusSample, StatusSnapshot,
            };

            let state = self.state.load_full();
            let (kind, single_node) = match state.as_ref() {
                Some(s) => {
                    let cfg = s.config.load();
                    (cfg.cluster.kind.clone(), cfg.cluster.is_single_node())
                }
                None => (self.boot_cluster_kind.clone(), self.boot_single_node),
            };

            let cluster = if single_node {
                ClusterStatusSample {
                    kind,
                    backend_up: None,
                    peers: None,
                }
            } else {
                // Peer count from the coordinator's own peer view (a
                // heartbeat cache or registry scan — cheap, possibly a
                // tick stale). Empty means the coordinator cannot
                // enumerate peers (a live one always sees itself), so
                // report unknown rather than a misleading zero. Bounded:
                // a wedged coordinator FFI must not wedge the ticker.
                let mut peers = None;
                if let Some(s) = state.as_ref() {
                    let rt = s.runtime.load_full();
                    if let Some(backend) = rt.plugin_registry().cluster_backend() {
                        peers = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            backend.list_peers(),
                        )
                        .await
                        .ok()
                        .map(|p| p.len() as u32)
                        .filter(|n| *n > 0);
                    }
                }
                ClusterStatusSample {
                    kind,
                    backend_up: cluster_backend_up(),
                    peers,
                }
            };

            let plugins = state
                .as_ref()
                .map(|s| {
                    s.runtime
                        .load()
                        .plugin_registry()
                        .loaded_plugins()
                        .into_iter()
                        .map(|p| PluginStatusSample {
                            id: p.id,
                            version: p.version,
                            state: p.state,
                            error: String::new(),
                            invocations: 0,
                        })
                        .collect()
                })
                .unwrap_or_default();

            // The digest the serving runtime resolved its `${secret.*}`
            // references with — a reload swaps the runtime, so a rotation
            // that landed shows up in the next report.
            let secrets_digest = state
                .as_ref()
                .map(|s| s.runtime.load().secrets_digest().to_owned())
                .unwrap_or_default();

            // Repeated in every report while it holds, so a report lost on
            // the way costs nothing, and the control plane counts the
            // refusal for as long as it lasts.
            let delivery_refusal = self.refusal.load_full().map(|r| DeliveryRefusalSample {
                reason: r.reason.to_owned(),
                proof_kid: r.proof_kid.clone(),
            });

            StatusSnapshot {
                plugins,
                warnings: Vec::new(),
                cluster: Some(cluster),
                secrets_digest,
                delivery_refusal,
            }
        }
    }

    /// Provider that reads the cp-client's lock-free
    /// `ArcSwap<Option<QuotaStatus>>` and translates each load
    /// into the gateway-internal `QuotaStatusInfo`.
    struct CpClientQuotaProvider {
        handle: Arc<ArcSwap<Option<QuotaStatus>>>,
    }

    impl QuotaStatusProvider for CpClientQuotaProvider {
        fn current(&self) -> Option<QuotaStatusInfo> {
            let guard = self.handle.load();
            let qs = guard.as_ref().as_ref()?;
            let until = qs.until.as_ref().and_then(|ts| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
            });
            let events_until = qs.events_until.as_ref().and_then(|ts| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
            });
            Some(QuotaStatusInfo {
                exhausted: qs.exhausted,
                until,
                remaining: qs.remaining,
                limit: qs.limit,
                rps_limit: qs.rps_limit,
                events: EventsPlan {
                    readers_limit: qs.event_subscriptions_limit,
                    deliveries_held: qs.events_exhausted,
                    ingest_held: qs.events_ingest_exhausted,
                    held_until: events_until,
                    types_limit: qs.event_types_limit,
                    retention_ms_limit: qs.event_retention_ms_limit,
                    retention_events_limit: qs.event_retention_events_limit,
                    retention_bytes_limit: qs.event_retention_bytes_limit,
                    retry_window_ms_limit: qs.event_retry_window_ms_limit,
                },
            })
        }
    }

    /// The agent's handles the runtime reads on its dispatch hot path.
    pub(super) struct RuntimeHooks {
        quota_status: Arc<ArcSwap<Option<QuotaStatus>>>,
        metrics: MetricsBuffer,
        dek: Arc<ArcSwap<Option<DekHandle>>>,
        capture_payloads: bool,
    }

    impl RuntimeHooks {
        pub(super) fn wire(&self, runtime: &mut GatewayRuntime) {
            runtime.set_cp_quota_status_provider(Arc::new(CpClientQuotaProvider {
                handle: self.quota_status.clone(),
            }));
            // Payload capture is the AND of the operator opt-in
            // (`control_plane.capture_payloads: true`) and the licence's
            // `payload_capture` feature; the CP drops a payload the licence
            // does not allow at ingest.
            runtime.set_tool_call_recorder(Arc::new(CpClientRecorder {
                buf: self.metrics.clone(),
                capture_payloads: self.capture_payloads,
                dek: self.dek.clone(),
            }));
        }
    }

    /// The plugin ids of the enabled entries of the plugin set a bundle binds,
    /// when it binds one.
    fn bound_plugin_ids(
        bundle: &mcpg_control_plane_client::ConfigBundle,
    ) -> Option<std::collections::BTreeSet<String>> {
        bundle.plugin_set.as_ref().map(|set| {
            set.entries
                .iter()
                .filter(|e| e.enabled)
                .map(|e| e.id.clone())
                .collect()
        })
    }

    /// Seed the gate with what the control plane delivered before this
    /// process started: the licence it last sent, proven for a day after the
    /// proof kept with it was signed, and the plugin set of the last bundle it
    /// pushed.
    pub(super) fn seed_from_state_dir(state_dir: &std::path::Path) {
        use crate::license_gate::{ChannelBinding, Delivery, Origin, cached_origin_of, platform};
        let delivery =
            mcpg_control_plane_client::license_delivery::load_cached(state_dir).map(|cached| {
                let origin = cached_origin_of(
                    &cached.license_jwt,
                    &cached.org_slug,
                    &cached.delivery_proof,
                    ChannelBinding {
                        nonce: &cached.channel_nonce,
                        instance_uid: &cached.instance_uid,
                    },
                    chrono::Utc::now().timestamp(),
                );
                match origin {
                    Origin::CachedProven { until } => info!(
                        org = %cached.org_slug,
                        until = %chrono::DateTime::from_timestamp(until, 0).unwrap_or_default(),
                        "control_plane: counting the licence mcpg.cloud proved before this start \
                         until the control plane answers, or until the proof is a day old"
                    ),
                    _ => info!(
                        org = %cached.org_slug,
                        "control_plane: using the licence delivered before this start"
                    ),
                }
                Delivery::Delivered {
                    license_jwt: cached.license_jwt,
                    org_slug: cached.org_slug,
                    origin,
                    refresh_failing: cached.refresh_failing,
                }
            });
        let bound = mcpg_control_plane_client::LkgCache::in_state_dir(state_dir)
            .load_bundle()
            .ok()
            .flatten()
            .map(|(_, bundle)| bound_plugin_ids(&bundle));
        platform::seed_from_cache(delivery, bound);
    }

    pub(super) async fn start(
        config: &AppConfig,
        config_sources: &[crate::config::ConfigSource],
        observability: &crate::observability::ObservabilityHandle,
    ) -> anyhow::Result<Option<CpAttachHandle>> {
        let Some(cp) = config.gateway.control_plane.as_ref() else {
            return Ok(None);
        };

        // The block is not a plugin spec, so the config-load resolver never
        // walks it; its two URLs get the same `${env.X}` pass here. That is
        // how a managed platform keeps the enrollment token out of the
        // rendered config: the block names an environment variable and a
        // Secret projected into the pod carries the value.
        let cp_url =
            crate::runtime::expr::resolve_env_in_string(&cp.url).context("control_plane.url")?;
        let enrollment_url = cp
            .enrollment_url
            .as_deref()
            .map(|u| {
                crate::runtime::expr::resolve_env_in_string(u)
                    .context("control_plane.enrollment_url")
            })
            .transpose()?
            .filter(|u| !u.trim().is_empty());

        // Sanity-check the config — Register requires either an
        // enrollment URL on first boot or cached creds in the
        // state dir. Bail with a clear message if neither.
        let creds_existed = std::path::Path::new(&cp.state_dir)
            .join("agent-creds.json")
            .exists();
        if enrollment_url.is_none() && !creds_existed {
            anyhow::bail!(
                "control_plane: no cached creds at {} — set enrollment_url on first boot",
                cp.state_dir
            );
        }

        std::fs::create_dir_all(&cp.state_dir)?;
        let agent_cfg = AgentRunnerConfig {
            cp_endpoint: cp_url.clone(),
            enrollment_url: enrollment_url.unwrap_or_default(),
            instance_uid: cp.instance_uid.clone().unwrap_or_else(default_instance_uid),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            state_dir: cp.state_dir.clone().into(),
            heartbeat_interval: heartbeat_interval(cp.heartbeat_interval_ms),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            bootstrap_ca_pem: cp.bootstrap_ca_pem.clone(),
            metrics_flush_interval: None,
        };

        seed_from_state_dir(std::path::Path::new(&cp.state_dir));

        // Late-bound AppState cell shared with the config-apply hook (bound
        // after AppState is built — see `CpAttachHandle::bind_state`).
        let config_state: Arc<ArcSwapOption<crate::app::AppState>> =
            Arc::new(ArcSwapOption::empty());
        let refusal = Arc::new(ArcSwapOption::empty());

        let runner = AgentRunner::new(agent_cfg)
            .with_config_applier(Arc::new(GatewayConfigApplier {
                state: config_state.clone(),
                boot_sources: config_sources.to_vec(),
                boot_provenance: config.cloud.provenance.clone(),
            }))
            .with_license_applier(Arc::new(GatewayLicenseApplier {
                state: config_state.clone(),
                refusal: refusal.clone(),
            }))
            .with_status_source(Arc::new(GatewayStatusSource {
                state: config_state.clone(),
                boot_cluster_kind: config.cluster.kind.clone(),
                boot_single_node: config.cluster.is_single_node(),
                refusal,
            }));

        let capture_payloads = cp.capture_payloads;
        let runtime_hooks = RuntimeHooks {
            quota_status: runner.quota_status_handle(),
            metrics: runner.metrics(),
            dek: runner.payload_dek_handle(),
            capture_payloads,
        };

        // Install the off-box log-capture sink so gateway tracing events flow
        // into the agent's log buffer (shipped as LogBatch → `mcpg cloud logs`).
        // Install-once; the tracing layer reads it lock-free per event.
        observability.set_log_sink(Arc::new(CpClientLogSink { buf: runner.logs() }));

        info!(
            cp_endpoint = %cp_url,
            state_dir = %cp.state_dir,
            capture_payloads,
            "control_plane: spawning agent"
        );

        // Spawn the agent. It registers, opens Channel, and
        // ships per-call samples + heartbeats forever (with
        // exponential-backoff reconnect).
        let _ = super::AGENT_SHUTDOWN.set(runner.shutdown_handle());
        let agent_handle = tokio::spawn(async move {
            if let Err(e) = runner.run().await {
                warn!(error = ?e, "control_plane: agent runner exited with error");
            }
        });
        // Outlives the agent: a gateway whose agent stopped still lapses.
        tokio::spawn(super::watch_running_licence(config_state.clone()));

        Ok(Some(CpAttachHandle {
            agent_handle,
            config_state,
            runtime_hooks,
        }))
    }

    /// Off-box log sink: translates a gateway `LogRecord` into the client's
    /// `LogLineSample` and records it in the agent's log buffer (the agent's
    /// flush loop ships it as a `LogBatch`). Drop-on-overflow inside the buffer
    /// keeps this non-blocking on the tracing emit path.
    struct CpClientLogSink {
        buf: mcpg_control_plane_client::LogBuffer,
    }

    impl crate::observability::log_bridge::LogSink for CpClientLogSink {
        fn record(&self, r: &mcpg_plugin_protocol::logs::LogRecord) {
            use mcpg_control_plane_client::{LogLevel, LogLineSample};
            use mcpg_plugin_protocol::logs::LogLevel as PLevel;
            let level = match r.level {
                PLevel::Trace => LogLevel::Trace,
                PLevel::Debug => LogLevel::Debug,
                PLevel::Info => LogLevel::Info,
                PLevel::Warn => LogLevel::Warn,
                PLevel::Error => LogLevel::Error,
            };
            self.buf.record(LogLineSample {
                at: chrono::DateTime::from_timestamp_nanos(r.timestamp_ns as i64),
                level,
                target: r.target.clone(),
                message: r.message.clone(),
                plugin_id: r.plugin_id.clone(),
            });
        }
    }

    /// Applies a CP-pushed config bundle by hot-reloading the running gateway in
    /// place. The bundle's `config_toml` carries the published config (YAML);
    /// empty means a plugin-set-only push with nothing to reload via config.
    /// The bundle's plugin set, when it carries one, bounds the plugins the
    /// gateway loads.
    struct GatewayConfigApplier {
        state: Arc<ArcSwapOption<crate::app::AppState>>,
        /// The layers this process booted from, for a push that arrives while
        /// it is still booting.
        boot_sources: Vec<crate::config::ConfigSource>,
        boot_provenance: crate::config::CloudProvenance,
    }

    #[async_trait::async_trait]
    impl mcpg_control_plane_client::ConfigApplier for GatewayConfigApplier {
        async fn apply(
            &self,
            bundle: &mcpg_control_plane_client::ConfigBundle,
        ) -> Result<(), String> {
            let bound_changed =
                crate::license_gate::platform::set_bound_plugins(bound_plugin_ids(bundle));
            if bundle.config_toml.is_empty() {
                // The running config is held to a changed plugin set now: a
                // gated plugin outside it that runs is withheld or held, and
                // one the config newly adds fails the reload, which the ack
                // says.
                return match self.state.load_full() {
                    Some(state) if bound_changed => crate::app::reapply_config(&state)
                        .await
                        .map_err(|e| format!("plugin set not applied: {e:#}")),
                    _ => Ok(()),
                };
            }
            let yaml = std::str::from_utf8(&bundle.config_toml)
                .map_err(|e| format!("pushed config not utf8: {e}"))?;
            let Some(state) = self.state.load_full() else {
                // The agent starts before boot finishes. A push of the file or
                // the platform render this process is booting from needs
                // nothing; anything else is reapplied by the next push or the
                // agent's reconnect.
                if pushed_matches_mounted_file(&self.boot_sources, &bundle.config_toml)
                    || is_operator_delivered(&self.boot_provenance, &self.boot_sources)
                {
                    return Ok(());
                }
                return Err("gateway AppState not yet bound".to_owned());
            };
            // The CP pushes the rendered file on every first connect; when that
            // is the file this gateway booted from, a reload would rebuild the
            // runtime to reach the config it already runs.
            let regate_if_bound_changed = || async {
                if !bound_changed {
                    return Ok(());
                }
                crate::app::reapply_config(&state)
                    .await
                    .map_err(|e| format!("plugin set not applied: {e:#}"))
            };
            if pushed_matches_mounted_file(&state.config_sources, &bundle.config_toml) {
                info!("control_plane: CP config matches the mounted file; no reload");
                return regate_if_bound_changed().await;
            }
            // A provisioned gateway runs the config its operator mounted: the
            // provisioner's render plus the operator's own overlay (default
            // backend plugins, registry cache, resource metadata, trace sink),
            // rolled into the pod on every publish. A control-plane push can
            // never carry that overlay, so applying one would strip it; the
            // mounted file stays authoritative and the push is acknowledged as
            // the state this pod already reached through its roll.
            if is_operator_delivered(
                &state.base_config.load().cloud.provenance,
                &state.config_sources,
            ) {
                info!(
                    "control_plane: provisioned gateway; the mounted config is authoritative, \
                     CP push acknowledged without reload"
                );
                return regate_if_bound_changed().await;
            }
            crate::app::reload_config_from_yaml(&state, yaml)
                .await
                .map_err(|e| format!("hot-reload failed: {e:#}"))
        }
    }

    /// Receives the org licence the control plane delivers. A running
    /// gateway is gated on it at once: it reloads when the licence covers
    /// less or more than what runs, and otherwise only refreshes the licence
    /// status it reports. A licence that does not verify never replaces one
    /// that does.
    pub(super) struct GatewayLicenseApplier {
        pub(super) state: Arc<ArcSwapOption<crate::app::AppState>>,
        /// What the status reports tell the control plane about the last
        /// delivery's cloud licence, shared with [`GatewayStatusSource`].
        pub(super) refusal: Arc<ArcSwapOption<crate::license_gate::DeliveryRefusal>>,
    }

    #[async_trait::async_trait]
    impl mcpg_control_plane_client::LicenseApplier for GatewayLicenseApplier {
        async fn apply_license(&self, delivery: &mcpg_control_plane_client::LicenseDelivery) {
            use crate::license_gate::{ChannelBinding, Delivery, judge_delivery, platform};
            let judged = judge_delivery(
                &delivery.license_jwt,
                &delivery.org_slug,
                &delivery.delivery_proof,
                ChannelBinding {
                    nonce: &delivery.channel_nonce,
                    instance_uid: &delivery.instance_uid,
                },
                chrono::Utc::now().timestamp(),
            );
            self.refusal.store(judged.refusal.map(Arc::new));
            let origin = judged.origin;
            let changed = platform::receive_delivery(Delivery::Delivered {
                license_jwt: delivery.license_jwt.clone(),
                org_slug: delivery.org_slug.clone(),
                origin,
                refresh_failing: delivery.refresh_failing,
            });
            if !changed {
                return;
            }
            // Until AppState is bound the booting gate is the reader.
            let Some(state) = self.state.load_full() else {
                return;
            };
            super::regate_running(&state).await;
        }

        async fn channel_slot_held(&self, retry_in: std::time::Duration) {
            crate::license_gate::platform::slot_held(retry_in);
        }
    }

    /// Whether this gateway's config was rendered by the platform and mounted
    /// by its operator: a file-backed layer whose loaded form carries the
    /// provisioner's placement provenance, which a hand-written config never
    /// legitimately has (the operator overwrites it at render).
    pub(super) fn is_operator_delivered(
        provenance: &crate::config::CloudProvenance,
        sources: &[crate::config::ConfigSource],
    ) -> bool {
        let has_file = sources
            .iter()
            .any(|s| matches!(s, crate::config::ConfigSource::File(_)));
        has_file && provenance.cluster_id.is_some() && provenance.namespace.is_some()
    }

    /// Whether `pushed` is, byte for byte (trailing whitespace aside), the last
    /// file-backed config layer as it is on disk right now. Inline layers and an
    /// unreadable file never match: a push is only skipped for a config the
    /// gateway can be shown to already have.
    pub(super) fn pushed_matches_mounted_file(
        sources: &[crate::config::ConfigSource],
        pushed: &[u8],
    ) -> bool {
        let Some(path) = sources.iter().rev().find_map(|s| match s {
            crate::config::ConfigSource::File(p) => Some(p),
            crate::config::ConfigSource::Inline { .. } => None,
        }) else {
            return false;
        };
        match std::fs::read(path) {
            Ok(on_disk) => on_disk.trim_ascii_end() == pushed.trim_ascii_end(),
            Err(_) => false,
        }
    }

    fn default_instance_uid() -> String {
        let hn = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "localhost".to_owned());
        format!("{hn}-{}", &uuid::Uuid::now_v7().to_string()[..8])
    }

    /// The heartbeat cadence for `gateway.control_plane.heartbeat_interval_ms`.
    /// Each heartbeat reply carries the CP's quota status, so the interval is
    /// held to 5–60 s: a long one would leave the gateway serving on a stale
    /// allowance, and zero would panic the ticker.
    pub(super) fn heartbeat_interval(configured_ms: Option<u64>) -> Duration {
        const DEFAULT: Duration = Duration::from_secs(30);
        const MIN: Duration = Duration::from_secs(5);
        const MAX: Duration = Duration::from_secs(60);
        configured_ms
            .map_or(DEFAULT, Duration::from_millis)
            .clamp(MIN, MAX)
    }
}

#[cfg(all(test, feature = "cp-attached"))]
mod tests {
    use super::attached::{heartbeat_interval, is_operator_delivered, pushed_matches_mounted_file};
    use crate::config::ConfigSource;
    use std::time::Duration;

    /// The key is milliseconds, and the cadence stays where the quota push
    /// needs it whatever a config asks for.
    #[test]
    fn heartbeat_interval_reads_milliseconds_and_stays_in_bounds() {
        assert_eq!(heartbeat_interval(None), Duration::from_secs(30));
        assert_eq!(heartbeat_interval(Some(30_000)), Duration::from_secs(30));
        assert_eq!(
            heartbeat_interval(Some(12_500)),
            Duration::from_millis(12_500)
        );
        assert_eq!(heartbeat_interval(Some(0)), Duration::from_secs(5));
        assert_eq!(heartbeat_interval(Some(30)), Duration::from_secs(5));
        assert_eq!(
            heartbeat_interval(Some(31_536_000)),
            Duration::from_secs(60)
        );
    }

    const MOUNTED: &[u8] = b"gateway:\n  server:\n    port: 8080\n";

    fn mounted_file(dir: &std::path::Path, bytes: &[u8]) -> ConfigSource {
        let path = dir.join("config.yaml");
        std::fs::write(&path, bytes).unwrap();
        ConfigSource::File(path)
    }

    #[test]
    fn identical_bytes_match_the_last_file_layer() {
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![
            ConfigSource::Inline {
                origin: "base64:".into(),
                yaml: "gateway: {}".into(),
            },
            mounted_file(dir.path(), MOUNTED),
        ];
        assert!(pushed_matches_mounted_file(&sources, MOUNTED));
        // A trailing newline is not a different config.
        assert!(pushed_matches_mounted_file(
            &sources,
            MOUNTED.strip_suffix(b"\n").unwrap()
        ));
    }

    /// Provenance alone does not make a gateway operator-delivered — it
    /// has to run from a mounted file — and a file alone does not either,
    /// since a self-hosted gateway attached to a CP also boots from a file.
    #[test]
    fn operator_delivery_needs_a_file_and_the_platforms_provenance() {
        use crate::config::CloudProvenance;
        let dir = tempfile::tempdir().unwrap();
        let file = vec![mounted_file(dir.path(), MOUNTED)];
        let inline = vec![ConfigSource::Inline {
            origin: "base64:".into(),
            yaml: "gateway: {}".into(),
        }];
        let stamped = CloudProvenance {
            cluster_id: Some("cell-1".into()),
            namespace: Some("tenant-acme".into()),
            ..CloudProvenance::default()
        };
        assert!(is_operator_delivered(&stamped, &file));
        assert!(!is_operator_delivered(&CloudProvenance::default(), &file));
        assert!(!is_operator_delivered(&stamped, &inline));
        let half = CloudProvenance {
            cluster_id: Some("cell-1".into()),
            ..CloudProvenance::default()
        };
        assert!(!is_operator_delivered(&half, &file));
    }

    #[test]
    fn different_bytes_do_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![mounted_file(dir.path(), MOUNTED)];
        assert!(!pushed_matches_mounted_file(
            &sources,
            b"gateway:\n  server:\n    port: 9090\n"
        ));
    }

    /// The comparison is against the file as it is now, not as it was at boot.
    #[test]
    fn the_file_is_re_read_on_every_push() {
        let dir = tempfile::tempdir().unwrap();
        let sources = vec![mounted_file(dir.path(), b"gateway: {}\n")];
        assert!(!pushed_matches_mounted_file(&sources, MOUNTED));
        std::fs::write(dir.path().join("config.yaml"), MOUNTED).unwrap();
        assert!(pushed_matches_mounted_file(&sources, MOUNTED));
    }

    /// Failed regates are retried on the next watch tick, then after 2, 4, 8
    /// and at most 16; one that applies resets the backoff, and what it
    /// applied is not gated again.
    #[test]
    fn a_failed_regate_backs_off_and_one_that_applies_resets_it() {
        let mut seen = super::LicenceWatch::default();
        let ticks_until_due = |seen: &mut super::LicenceWatch| {
            (1..=64)
                .find(|_| seen.due(None, true, 7))
                .expect("due again")
        };
        assert!(seen.due(None, true, 7));
        let waits: Vec<u32> = (0..6)
            .map(|_| {
                let wait = seen.failed();
                assert_eq!(ticks_until_due(&mut seen), wait);
                wait
            })
            .collect();
        assert_eq!(waits, [1, 2, 4, 8, 16, 16]);

        seen.applied(Some(100), 7);
        assert!(!seen.due(Some(100), true, 7), "applied once");
        assert!(
            seen.due(Some(100), true, 8),
            "a new delivery is due at once"
        );
        assert!(seen.due(Some(200), false, 7), "so is a new lapse");
        assert_eq!(seen.failed(), 1, "the backoff starts over");
    }

    /// A running gateway that a delivery's own regate caught up while the
    /// watch backed off owes the next lapse no backoff.
    #[test]
    fn a_gateway_caught_up_elsewhere_gates_the_next_lapse_at_once() {
        let mut seen = super::LicenceWatch::default();
        assert!(seen.due(None, true, 7));
        for _ in 0..5 {
            seen.failed();
        }
        assert!(!seen.due(None, false, 8), "caught up");
        assert!(seen.due(Some(100), false, 8), "the lapse is gated at once");
        assert_eq!(seen.failed(), 1, "the backoff starts over");
    }

    fn enterprise_licence() -> String {
        use mcpg_control_plane_license::license::{
            self, AUDIENCE_GATEWAY_MANAGED, IssuerRole, KeyEnvironment, LicenseClaims,
        };
        let mut claims = LicenseClaims::community("mcpg-cp");
        claims.iss = "https://license.test".into();
        claims.exp = chrono::Utc::now().timestamp() + 3600;
        let (entitlements, quotas) = license::plan_envelope("enterprise");
        claims.plugin_entitlements = entitlements;
        claims.quotas = quotas;
        claims.features = license::features_for("enterprise");
        claims.plan = "enterprise".into();
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = "acme".into();
        mcpg_control_plane_license::trust::test_override::issue(
            IssuerRole::Cloud,
            KeyEnvironment::Production,
            &claims,
        )
    }

    /// A restart reads the cached delivery back proven when the proof kept
    /// with it verifies again for the nonce and instance it was kept with,
    /// and as a plain cached delivery when the proof is gone or was edited.
    #[tokio::test]
    async fn a_restart_reads_the_cached_proof_back() {
        use crate::license_gate::{Delivery, Origin, platform};
        use mcpg_control_plane_client::license_delivery::{LicenseDelivery, save_cached};
        use mcpg_control_plane_license::delivery::{LAST_KNOWN_GOOD_SECS, test_proof};
        use mcpg_control_plane_license::license::{IssuerRole, KeyEnvironment};
        let _platform = platform::test_lock().await;
        let key = mcpg_control_plane_license::trust::test_override::trusted_signing_key(
            IssuerRole::Platform,
            KeyEnvironment::Production,
        );
        let licence = enterprise_licence();
        let signed_at = chrono::Utc::now().timestamp();
        let proof = test_proof::sign(
            &test_proof::claims("nonce-1", "gw-1", "acme", &licence, signed_at),
            &key,
        );
        let cached = LicenseDelivery {
            license_jwt: licence.clone(),
            org_slug: "acme".into(),
            refresh_failing: false,
            delivery_proof: proof,
            channel_nonce: "nonce-1".into(),
            instance_uid: "gw-1".into(),
        };
        let origin_after_seed = |delivery: &LicenseDelivery| {
            let dir = tempfile::tempdir().unwrap();
            save_cached(dir.path(), delivery).unwrap();
            super::attached::seed_from_state_dir(dir.path());
            match &*platform::delivery_when(true) {
                Delivery::Delivered { origin, .. } => *origin,
                other => panic!("seeded {other:?}"),
            }
        };
        assert_eq!(
            origin_after_seed(&cached),
            Origin::CachedProven {
                until: signed_at + LAST_KNOWN_GOOD_SECS
            }
        );
        let edited = LicenseDelivery {
            instance_uid: "gw-2".into(),
            ..cached.clone()
        };
        assert_eq!(origin_after_seed(&edited), Origin::Cached);
        let unproven = LicenseDelivery {
            delivery_proof: String::new(),
            ..cached
        };
        assert_eq!(origin_after_seed(&unproven), Origin::Cached);

        platform::clear_seed();
        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::Pending);
    }

    /// A running gateway on `config` whose runtime was gated on `license`.
    fn running_state(
        config: crate::config::AppConfig,
        license: &crate::license_gate::GateOutcome,
    ) -> crate::app::AppState {
        use arc_swap::ArcSwap;
        use std::sync::Arc;
        let mut runtime = crate::runtime::GatewayRuntime::new(
            "mcpg",
            "0.1.0",
            "127.0.0.1:8787",
            "/health",
            "/mcp",
            "info",
            Vec::new(),
            true,
        );
        runtime.set_license_state(license.into());
        crate::app::AppState {
            config: Arc::new(ArcSwap::from_pointee(config.clone())),
            base_config: Arc::new(ArcSwap::from_pointee(config)),
            registry_overlay: Arc::new(ArcSwap::from_pointee(
                crate::runtime::registry_sync::RegistryOverlay::default(),
            )),
            runtime: Arc::new(ArcSwap::from_pointee(runtime)),
            session_store: Arc::new(
                crate::runtime::session_store::KvBackedSessionStore::new_in_memory(
                    crate::runtime::SessionStoreConfig::default(),
                ),
            ),
            observability: Arc::new(crate::observability::ObservabilityHandle::default()),
            config_sources: Vec::new(),
            sse_stream_counts: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            config_overlay: Arc::new(ArcSwap::from_pointee(serde_json::Value::Object(
                serde_json::Map::new(),
            ))),
            policy_chain: Arc::new(ArcSwap::from_pointee(Vec::new())),
            plugin_health_prober: Arc::new(tokio::sync::Mutex::new(None)),
            secret_watcher: Arc::new(tokio::sync::Mutex::new(None)),
            #[cfg(feature = "governance-quotas")]
            quota_gate: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// A lower licence whose reload fails leaves the running gateway, and the
    /// licence status it reports, as they were, and is tried again until a
    /// reload applies it: the backend the licence no longer covers is then
    /// withheld, and the status says so.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lower_licence_whose_reload_fails_is_applied_by_a_retry() {
        crate::license_gate::with_reported_status(lower_licence_retry()).await;
    }

    async fn lower_licence_retry() {
        use crate::license_gate::{
            Delivery, Origin, gate_at_reload, platform, report, reported_status as current_status,
        };
        let _platform = platform::test_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let config = |cluster: &str| -> crate::config::AppConfig {
            serde_yaml::from_str(&format!(
                "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n    \
                 enrollment_url: http://127.0.0.1:9\n    state_dir: {}\n{cluster}plugins:\n  \
                 - id: dev.mcpg.backend.kafka\n    class: backend\n    \
                 source: {{ path: /tmp/x.so }}\n",
                dir.path().display()
            ))
            .unwrap()
        };
        // A key variable that is never set fails every reload after the gate.
        let unreloadable =
            config("cluster:\n  state_encryption_key_env: MCPG_TEST_NEVER_SET_STATE_KEY\n");
        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::received(
            enterprise_licence(),
            "acme".into(),
            Origin::Proven,
        ));
        let running = gate_at_reload(&unreloadable, &Default::default()).expect("covered");
        assert!(running.withheld.is_empty());
        report(&running);
        let state = running_state(unreloadable, &running);

        platform::set_delivery(Delivery::received(
            String::new(),
            "acme".into(),
            Origin::Proven,
        ));
        let generation = platform::generation();
        let mut seen = super::LicenceWatch::default();
        super::check_running_licence(&state, &mut seen).await;
        assert_eq!(seen.generation, None, "not applied, so not recorded");
        assert_eq!(seen.failures, 1);
        assert!(state.runtime.load().license_state().withheld.is_empty());
        let status = current_status().expect("published");
        assert!(
            status.withheld.is_empty(),
            "the backend still runs: {status:?}"
        );

        state.base_config.store(std::sync::Arc::new(config("")));
        super::check_running_licence(&state, &mut seen).await;
        assert_eq!(seen.generation, Some(generation));
        assert_eq!(seen.failures, 0);
        assert_eq!(
            state.runtime.load().license_state().withheld,
            ["dev.mcpg.backend.kafka"]
        );
        assert_eq!(
            current_status().expect("published").withheld,
            ["dev.mcpg.backend.kafka"]
        );

        platform::set_delivery(Delivery::Pending);
    }

    /// A backend a bound plugin set took back stays withheld: the deliveries
    /// and reloads after it are not refused over it, so a lower licence still
    /// applies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_the_bound_set_took_back_never_blocks_a_later_licence() {
        crate::license_gate::with_reported_status(bound_set_took_back_a_backend()).await;
    }

    async fn bound_set_took_back_a_backend() {
        use crate::license_gate::{
            Delivery, Origin, gate_at_reload, platform, report, reported_status as current_status,
        };
        let _platform = platform::test_lock().await;
        let dir = tempfile::tempdir().unwrap();
        let config: crate::config::AppConfig = serde_yaml::from_str(&format!(
            "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n    \
             enrollment_url: http://127.0.0.1:9\n    state_dir: {}\nplugins:\n  \
             - id: dev.mcpg.backend.kafka\n    class: backend\n    \
             source: {{ path: /tmp/x.so }}\n",
            dir.path().display()
        ))
        .unwrap();
        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::received(
            enterprise_licence(),
            "acme".into(),
            Origin::Proven,
        ));
        let running = gate_at_reload(&config, &Default::default()).expect("covered");
        report(&running);
        let state = running_state(config, &running);

        platform::set_bound_plugins(Some(["dev.mcpg.backend.http".to_owned()].into()));
        assert!(super::regate_running(&state).await, "taken back");
        assert_eq!(
            state.runtime.load().license_state().withheld,
            ["dev.mcpg.backend.kafka"]
        );

        platform::set_delivery(Delivery::received(
            String::new(),
            "acme".into(),
            Origin::Proven,
        ));
        assert!(
            super::regate_running(&state).await,
            "the lower licence reaches the running gateway"
        );
        let status = current_status().expect("published");
        assert_eq!(status.plan, "community");
        assert_eq!(status.withheld, ["dev.mcpg.backend.kafka"]);
        crate::app::reapply_config(&state)
            .await
            .expect("a reload of the same config is not refused over it");

        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::Pending);
    }

    #[test]
    fn no_file_layer_or_unreadable_file_never_matches() {
        let inline_only = vec![ConfigSource::Inline {
            origin: "base64:".into(),
            yaml: String::from_utf8(MOUNTED.to_vec()).unwrap(),
        }];
        assert!(!pushed_matches_mounted_file(&inline_only, MOUNTED));
        assert!(!pushed_matches_mounted_file(&[], MOUNTED));

        let dir = tempfile::tempdir().unwrap();
        let missing = vec![ConfigSource::File(dir.path().join("gone.yaml"))];
        assert!(!pushed_matches_mounted_file(&missing, MOUNTED));
    }

    /// A delivery whose cloud licence counts for nothing, for want of a proof
    /// that verifies, rides on every status report the gateway sends its
    /// control plane, with the refused proof's `kid` and never the licence,
    /// until a delivery the gateway counts replaces it.
    #[tokio::test]
    async fn a_refused_delivery_rides_on_every_status_report_until_one_counts() {
        use std::sync::Arc;

        use super::attached::{GatewayLicenseApplier, GatewayStatusSource};
        use crate::license_gate::{Delivery, platform};
        use arc_swap::ArcSwapOption;
        use mcpg_control_plane_client::{
            DeliveryRefusalSample, LicenseApplier, LicenseDelivery, StatusSource,
        };
        use mcpg_control_plane_license::delivery::{new_nonce, test_proof};
        use mcpg_control_plane_license::license::{IssuerRole, KeyEnvironment};
        use mcpg_control_plane_license::trust::{test_override, thumbprint_kid};

        let _platform = platform::test_lock().await;
        let state = Arc::new(ArcSwapOption::empty());
        let refusal = Arc::new(ArcSwapOption::empty());
        let applier = GatewayLicenseApplier {
            state: state.clone(),
            refusal: refusal.clone(),
        };
        let source = GatewayStatusSource {
            state,
            boot_cluster_kind: "single_node".into(),
            boot_single_node: true,
            refusal,
        };
        let licence = enterprise_licence();
        let nonce = new_nonce();
        let delivery = |proof: String| LicenseDelivery {
            license_jwt: licence.clone(),
            org_slug: "acme".into(),
            refresh_failing: false,
            delivery_proof: proof,
            channel_nonce: nonce.clone(),
            instance_uid: "gw-1".into(),
        };
        let signed = |key: &ed25519_dalek::SigningKey, nonce: &str| {
            test_proof::sign(
                &test_proof::claims(
                    nonce,
                    "gw-1",
                    "acme",
                    &licence,
                    chrono::Utc::now().timestamp(),
                ),
                key,
            )
        };
        let platform_key =
            test_override::trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Production);

        assert_eq!(source.snapshot().await.delivery_refusal, None);
        applier.apply_license(&delivery(String::new())).await;
        for _ in 0..2 {
            assert_eq!(
                source.snapshot().await.delivery_refusal,
                Some(DeliveryRefusalSample {
                    reason: "no_proof".into(),
                    proof_kid: String::new(),
                })
            );
        }

        applier
            .apply_license(&delivery(signed(&platform_key, &new_nonce())))
            .await;
        let reported = source.snapshot().await.delivery_refusal;
        assert_eq!(
            reported,
            Some(DeliveryRefusalSample {
                reason: "proof_refused".into(),
                proof_kid: thumbprint_kid(&platform_key.verifying_key()),
            })
        );
        assert!(!format!("{reported:?}").contains(&licence));

        applier
            .apply_license(&delivery(signed(&platform_key, &nonce)))
            .await;
        assert_eq!(source.snapshot().await.delivery_refusal, None);

        platform::set_delivery(Delivery::Pending);
    }
}
