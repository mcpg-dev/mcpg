//! Control Plane attachment configuration.
//!
//! See `apps/gateway/src/runtime/cp/attach.rs` for the wiring logic.

use serde::{Deserialize, Serialize};

/// Control Plane attachment config. See
/// `apps/gateway/src/runtime/cp/attach.rs` for the wiring logic.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneAttachConfig {
    /// gRPC URL of the Control Plane
    /// (e.g. `"https://cp.example.com:7844"`).
    pub url: String,
    /// One-time enrollment URL minted by the CP UI. Required on
    /// first boot; subsequent boots reuse the cached creds in
    /// `state_dir`.
    #[serde(default)]
    pub enrollment_url: Option<String>,
    /// Stable per-instance id. Defaults to
    /// `${HOSTNAME}-${uuid7-prefix}` when unset.
    #[serde(default)]
    pub instance_uid: Option<String>,
    /// Where to persist agent creds (`agent-creds.json`) and the
    /// LKG cache. Defaults to `./mcpg-cp-state`.
    #[serde(default = "default_cp_state_dir")]
    pub state_dir: String,
    /// Seconds between heartbeats. Default 30s.
    #[serde(default)]
    pub heartbeat_interval_ms: Option<u64>,
    /// PEM-encoded CA bundle to trust on the very first connect
    /// (Register), before the agent has its own creds. Once
    /// Register completes, the CP-issued cert/key/ca_chain trio
    /// supplants this. Optional; only required when the CP gRPC
    /// listener is TLS and the operator hasn't pre-populated a
    /// previous run's `agent-creds.json`.
    #[serde(default)]
    pub bootstrap_ca_pem: Option<String>,
    /// **Enterprise opt-in.** When `true`, the
    /// gateway captures the JSON-serialized request arguments +
    /// response of each tool call and ships them in the
    /// `MetricsReport` (Channel-encrypted; the CP further
    /// encrypts at-rest with a per-tenant KMS-derived key). The
    /// captured bytes can contain PII / secrets, so this is
    /// off by default; the CP also gates ingest on the active
    /// license carrying the `payload_capture` feature flag, so
    /// flipping this `true` without a matching license is a
    /// no-op (samples ship but CP drops the payload bytes).
    #[serde(default)]
    pub capture_payloads: bool,
}

fn default_cp_state_dir() -> String {
    "./mcpg-cp-state".to_owned()
}
