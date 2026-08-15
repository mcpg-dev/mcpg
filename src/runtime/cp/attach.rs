//! Optional Control Plane attachment — gateway side.
//!
//! When the `cp-attached` Cargo feature is enabled and operator
//! config provides a CP endpoint + enrollment URL, this module:
//!
//! 1. Constructs an `AgentRunner` (Register → open Channel →
//!    heartbeat + apply ConfigUpdate).
//! 2. Bridges its `MetricsBuffer` into the gateway's
//!    `runtime::cp_metrics::ToolCallRecorder` slot via a small
//!    adapter, so every tool call recorded at dispatch time
//!    flows over Channel as a `MetricsReport`.
//! 3. Returns a `JoinHandle` for graceful shutdown.
//!
//! When the feature is OFF, [`wire_if_configured`] is a no-op
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
    /// hook so a pushed config can hot-reload the running gateway. The agent is
    /// wired before `AppState` exists (it needs `&mut runtime`), so the state is
    /// bound afterwards via [`CpAttachHandle::bind_state`].
    #[cfg(feature = "cp-attached")]
    config_state: std::sync::Arc<arc_swap::ArcSwapOption<crate::app::AppState>>,
}

impl CpAttachHandle {
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
    pub fn bind_state(&self, state: crate::app::AppState) {
        #[cfg(feature = "cp-attached")]
        self.config_state.store(Some(std::sync::Arc::new(state)));
        #[cfg(not(feature = "cp-attached"))]
        let _ = state;
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

/// Attach the gateway to a Control Plane if config requests it.
/// Must be called before `runtime` is wrapped in `Arc<ArcSwap>`
/// so the recorder slot can be set with `&mut runtime`.
///
/// Returns `Ok(None)` when no attachment is configured (or the
/// feature is off) — the gateway runs standalone with the
/// default `NoopRecorder`.
pub async fn wire_if_configured(
    runtime: &mut GatewayRuntime,
    config: &AppConfig,
    observability: &crate::observability::ObservabilityHandle,
) -> anyhow::Result<Option<CpAttachHandle>> {
    #[cfg(not(feature = "cp-attached"))]
    {
        let _ = (runtime, config, observability);
        // Feature off — nothing to do. The config block, if
        // present, is silently ignored (operators get a clear
        // error from `cargo build` if they forget the feature).
        Ok(None)
    }
    #[cfg(feature = "cp-attached")]
    {
        attached::wire(runtime, config, observability).await
    }
}

#[cfg(feature = "cp-attached")]
mod attached {
    use std::sync::Arc;
    use std::time::Duration;

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
    use crate::runtime::cp_quota::{QuotaStatusInfo, QuotaStatusProvider};

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
            Some(QuotaStatusInfo {
                exhausted: qs.exhausted,
                until,
                remaining: qs.remaining,
                limit: qs.limit,
                rps_limit: qs.rps_limit,
            })
        }
    }

    pub(super) async fn wire(
        runtime: &mut GatewayRuntime,
        config: &AppConfig,
        observability: &crate::observability::ObservabilityHandle,
    ) -> anyhow::Result<Option<CpAttachHandle>> {
        let Some(cp) = config.gateway.control_plane.as_ref() else {
            return Ok(None);
        };

        // Sanity-check the config — Register requires either an
        // enrollment URL on first boot or cached creds in the
        // state dir. Bail with a clear message if neither.
        let creds_existed = std::path::Path::new(&cp.state_dir)
            .join("agent-creds.json")
            .exists();
        if cp.enrollment_url.is_none() && !creds_existed {
            anyhow::bail!(
                "control_plane: no cached creds at {} — set enrollment_url on first boot",
                cp.state_dir
            );
        }

        std::fs::create_dir_all(&cp.state_dir)?;
        let agent_cfg = AgentRunnerConfig {
            cp_endpoint: cp.url.clone(),
            enrollment_url: cp.enrollment_url.clone().unwrap_or_default(),
            instance_uid: cp.instance_uid.clone().unwrap_or_else(default_instance_uid),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            state_dir: cp.state_dir.clone().into(),
            heartbeat_interval: Duration::from_secs(cp.heartbeat_interval_ms.unwrap_or(30)),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            bootstrap_ca_pem: cp.bootstrap_ca_pem.clone(),
        };

        // Late-bound AppState cell shared with the config-apply hook (bound
        // after AppState is built — see `CpAttachHandle::bind_state`).
        let config_state: Arc<ArcSwapOption<crate::app::AppState>> =
            Arc::new(ArcSwapOption::empty());

        let runner =
            AgentRunner::new(agent_cfg).with_config_applier(Arc::new(GatewayConfigApplier {
                state: config_state.clone(),
            }));

        // Wire the CP-pushed quota status provider before
        // spawning the agent so the dispatch hot path sees the
        // (currently empty) handle from the very first call.
        // After Register + the first heartbeat reply, the handle
        // will start carrying real `QuotaStatus` values.
        runtime.set_cp_quota_status_provider(Arc::new(CpClientQuotaProvider {
            handle: runner.quota_status_handle(),
        }));

        // Wire the recorder BEFORE spawning the agent so the
        // very first tool call after boot records a sample.
        // Payload capture is the AND of: operator opt-in
        // (`control_plane.capture_payloads: true`) AND license
        // entitlement (`payload_capture` in `features`). The
        // license can't be read at this exact moment (the
        // gateway hasn't yet pulled its initial ConfigBundle),
        // so we defer the license check to the dispatch hot
        // path — but for now we surface the *operator* opt-in
        // here. If the license later denies, the CP will simply
        // drop the payload at ingest time.
        let capture_payloads = cp.capture_payloads;
        runtime.set_tool_call_recorder(Arc::new(CpClientRecorder {
            buf: runner.metrics(),
            capture_payloads,
            dek: runner.payload_dek_handle(),
        }));

        // Install the off-box log-capture sink so gateway tracing events flow
        // into the agent's log buffer (shipped as LogBatch → `mcpg cloud logs`).
        // Install-once; the tracing layer reads it lock-free per event.
        observability.set_log_sink(Arc::new(CpClientLogSink { buf: runner.logs() }));

        info!(
            cp_endpoint = %cp.url,
            state_dir = %cp.state_dir,
            capture_payloads,
            "control_plane: wired tool-call recorder; spawning agent"
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

        Ok(Some(CpAttachHandle {
            agent_handle,
            config_state,
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
    struct GatewayConfigApplier {
        state: Arc<ArcSwapOption<crate::app::AppState>>,
    }

    #[async_trait::async_trait]
    impl mcpg_control_plane_client::ConfigApplier for GatewayConfigApplier {
        async fn apply(
            &self,
            bundle: &mcpg_control_plane_client::ConfigBundle,
        ) -> Result<(), String> {
            if bundle.config_toml.is_empty() {
                return Ok(());
            }
            let yaml = std::str::from_utf8(&bundle.config_toml)
                .map_err(|e| format!("pushed config not utf8: {e}"))?;
            let Some(state) = self.state.load_full() else {
                // The agent connected before AppState was bound — rare; the next
                // push (or the agent's reconnect pull) reapplies.
                return Err("gateway AppState not yet bound".to_owned());
            };
            crate::app::reload_config_from_yaml(&state, yaml)
                .await
                .map_err(|e| format!("hot-reload failed: {e}"))
        }
    }

    fn default_instance_uid() -> String {
        let hn = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .unwrap_or_else(|| "localhost".to_owned());
        format!("{hn}-{}", &uuid::Uuid::now_v7().to_string()[..8])
    }
}
