//! Pipeline store — persistence for multi-step pipeline executions.
//!
//! Stores suspension state, pending server requests, and buffered
//! delivery messages so any cluster node can resume a pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::config::PipelineStepConfig;

// --- Types ---

/// MCP surface that originated a pipeline execution. Persisted on the
/// suspension state so the resumption path projects the completed
/// result onto the correct wire shape — a `tools/call` returns the
/// raw `ToolCallResult`, a `prompts/get` must project onto
/// `PromptGetResult` (`{ messages: [...] }`), and a `resources/read`
/// onto `ResourceReadResult`. Defaults to `Tool` so pre-existing
/// persisted states (written before this field) decode unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineSurface {
    #[default]
    Tool,
    Prompt,
    Resource,
}

/// Serializable state of a multi-step pipeline execution. Persisted to the
/// pipeline store on each suspension so any cluster node can resume it when
/// the client responds to a server-initiated request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecutionState {
    /// Unique pipeline execution ID (= gateway_request_id of the tools/call).
    pub pipeline_id: String,
    /// MCP session this pipeline belongs to.
    pub session_id: String,
    /// Original JSON-RPC request ID from the tools/call.
    pub original_jsonrpc_id: Value,
    /// Tool name that triggered this pipeline.
    pub tool_name: String,

    /// Pipeline step definitions (immutable copy from config).
    pub steps: Vec<PipelineStepConfig>,

    /// Index of the next step to execute (0-based).
    pub current_step_index: usize,
    /// Results of completed steps, keyed by step id.
    pub completed_steps: BTreeMap<String, StepResult>,
    /// Original tool arguments.
    pub original_args: Value,
    /// Serialized request context (identity, trust, session).
    pub request_context: crate::runtime::RequestContext,

    /// Pipeline lifecycle timestamps.
    pub created_at: DateTime<Utc>,
    pub suspended_at: Option<DateTime<Utc>>,
    pub pipeline_timeout_ms: u64,

    /// Elicitation/sampling tracking.
    pub pending_server_request_id: Option<String>,
    pub elicitation_timeout_ms: Option<u64>,

    /// Task correlation. Set when the pipeline runs inside a
    /// task-augmented `tools/call`. When present, the resume handler
    /// persists the terminal envelope on the task instead of emitting a
    /// deferred tool result.
    #[serde(default)]
    pub related_task_id: Option<String>,

    /// Snapshot of the client's capability tree at the time the pipeline
    /// started. Persisted so resume paths can enforce capability gating on
    /// later suspending steps.
    #[serde(default)]
    pub client_capabilities: crate::protocol::ClientCapabilities,

    /// CAS fencing: incremented on every state mutation.
    pub state_version: u64,

    /// MCP surface that originated this pipeline (tool / prompt /
    /// resource). The resumption path reads it to project the
    /// completed pipeline result onto the right wire shape. Defaults
    /// to `Tool` for states persisted before this field existed.
    #[serde(default)]
    pub surface: PipelineSurface,
}

/// Result of a single completed pipeline step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub output: Value,
    pub is_error: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingServerRequest {
    /// The JSON-RPC request ID assigned by the server.
    pub server_request_id: String,
    /// Pipeline this request belongs to.
    pub pipeline_id: String,
    /// Session this request belongs to.
    pub session_id: String,
    /// Pipeline step that generated this request.
    pub step_id: String,
    /// How long to wait for the client's response (ms).
    pub timeout_ms: u64,
    /// When this request was created.
    pub created_at: DateTime<Utc>,
}

/// A message routed through the delivery bus to a session's SSE stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryMessage {
    pub kind: DeliveryKind,
    pub jsonrpc_message: Value,
    /// The coordinator-KV backlog id this delivery is stored under
    /// (`delivery:{session}:{delivery_id}`). Populated on the live bus copy
    /// (so the SSE event can be tagged with it) and re-stamped onto each
    /// drained backlog copy from its KV key. Empty on a fresh message before
    /// it is stored. Gateway-internal book-keeping — it is NOT part of the
    /// JSON-RPC body sent to the client (`jsonrpc_message` is). `#[serde(default)]`
    /// keeps pre-existing persisted/bus messages decodable unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub delivery_id: String,
}

/// Discriminant for the type of delivery message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryKind {
    ServerRequest,
    DeferredToolResult,
    PipelineError,
    ProgressNotification,
    /// A resource has been updated (for subscribers).
    ResourceUpdated,
    /// A generic notification (list_changed, etc.).
    Notification,
}

// --- Trait ---

/// Backend-agnostic persistence for pipeline state and pending deliveries.
pub trait PipelineStore: Send + Sync + std::fmt::Debug {
    /// Save or update pipeline execution state.
    fn save_pipeline(&self, state: &PipelineExecutionState) -> anyhow::Result<()>;

    /// Load pipeline state by pipeline_id.
    fn load_pipeline(&self, pipeline_id: &str) -> anyhow::Result<Option<PipelineExecutionState>>;

    /// Attempt to claim a pipeline for execution by CAS on state_version.
    /// Returns true if the claim succeeded (state_version matched and was incremented).
    fn try_claim_pipeline(&self, pipeline_id: &str, expected_version: u64) -> anyhow::Result<bool>;

    /// Patch the `original_jsonrpc_id` onto a just-suspended pipeline row,
    /// guarded so the write can neither resurrect a reaped row nor clobber a
    /// row whose `state_version` has moved on (a concurrent claim/resume). The
    /// write applies only when the row still exists at `expected_version`;
    /// returns `true` when it was applied, `false` when the row was gone or the
    /// version had advanced (in which case the caller should not retry — the
    /// pipeline has already been claimed or reaped). The persisted
    /// `state_version` is left unchanged so it does not interfere with the
    /// resume-claim CAS.
    fn set_original_jsonrpc_id_if_version(
        &self,
        pipeline_id: &str,
        expected_version: u64,
        original_jsonrpc_id: &Value,
    ) -> anyhow::Result<bool>;

    /// Delete pipeline state after completion.
    fn delete_pipeline(&self, pipeline_id: &str) -> anyhow::Result<()>;

    /// Save a pending server request record.
    fn save_pending_server_request(&self, request: &PendingServerRequest) -> anyhow::Result<()>;

    /// Load a pending server request by server_request_id.
    fn load_pending_server_request(
        &self,
        server_request_id: &str,
    ) -> anyhow::Result<Option<PendingServerRequest>>;

    /// Delete a pending server request after handling.
    fn delete_pending_server_request(&self, server_request_id: &str) -> anyhow::Result<()>;

    /// Store a pending delivery message for a session (reconnection fallback).
    fn store_pending_delivery(
        &self,
        session_id: &str,
        message: &DeliveryMessage,
    ) -> anyhow::Result<String>;

    /// Load and delete all pending deliveries for a session. Each returned
    /// [`DeliveryMessage`] carries its originating `delivery_id` (from the KV
    /// key) so the caller can tag SSE events with it.
    fn take_pending_deliveries(&self, session_id: &str) -> anyhow::Result<Vec<DeliveryMessage>>;

    /// Delete a single buffered delivery by its id WITHOUT draining the rest.
    /// Used by the reconnect ack-prune: when a client reconnects echoing a
    /// delivery-tagged `Last-Event-Id`, the row it already received is removed
    /// so the later drain does not replay it. Idempotent — a
    /// missing key is a no-op.
    fn delete_delivery(&self, session_id: &str, delivery_id: &str) -> anyhow::Result<()>;

    /// List pipeline IDs that have exceeded their timeout.
    fn list_expired_pipelines(&self) -> anyhow::Result<Vec<String>>;

    /// List pipeline IDs that are SUSPENDED past their per-step
    /// `elicitation_timeout_ms` (measured from `suspended_at`), distinct
    /// from the whole-pipeline `pipeline_timeout_ms` sweep. A suspended
    /// pipeline whose elicitation bound has elapsed must be reaped with a
    /// terminal timeout error to the caller. Returns
    /// `(pipeline_id, session_id, original_jsonrpc_id)` so the caller can
    /// deliver that terminal error before deleting the state.
    fn list_elicitation_timed_out(&self) -> anyhow::Result<Vec<(String, String, Value)>>;

    /// Find a SUSPENDED pipeline by the original JSON-RPC request id (rendered
    /// to string) that started it, scoped to a session. Used by the
    /// cancellation path to locate the persisted state for a suspended
    /// pipeline (which holds no live cancellation token on any replica).
    /// Returns the full state so the caller can authorize the cancel against
    /// the persisted owner before claiming + deleting it.
    fn find_suspended_by_jsonrpc_id(
        &self,
        session_id: &str,
        original_jsonrpc_id: &str,
    ) -> anyhow::Result<Option<PipelineExecutionState>>;
}

// --- In-Memory Implementation ---

// ===========================================================================
// KvBackedPipelineStore — single impl over the orthogonal KvState primitive
// ===========================================================================

/// Pipeline store backed by any [`mcpg_cluster_api::KeyValueStore`] impl.
///
/// One concrete struct works for every distributed backend (file,
/// redis, nats, …) — the choice of backend is just which
/// `Arc<dyn KeyValueStore>` operators wired in.
///
/// The trait surface is sync (matches the existing call sites);
/// the impl bridges via `tokio::task::block_in_place` +
/// `Handle::current().block_on(...)`.
///
/// `try_claim_pipeline` is a cluster-strict single-winner claim:
/// the `state_version` check fast-rejects stale claims, and an atomic
/// `KeyValueStore::put_if_absent` on a per-`(pipeline, version)` marker
/// is the authoritative gate — so concurrent resumes of the same
/// suspended pipeline across replicas resolve to exactly one winner
/// (no last-writer-wins double-resume).
pub struct KvBackedPipelineStore {
    state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    /// Wall-clock TTL applied to every pipeline key (5 minutes).
    pipeline_ttl: std::time::Duration,
    /// TTL applied to buffered terminal deliveries. Held >= `pipeline_ttl`
    /// so a late legacy reconnect can still drain a result produced by a
    /// pipeline that is itself still alive.
    delivery_ttl: std::time::Duration,
    pending_request_ttl: std::time::Duration,
    /// Monotonic counter for delivery-id ordering. Pre-pended to the
    /// random UUID part so `list_prefix` returns deliveries in
    /// insertion order even when bursts arrive within the same
    /// millisecond.
    delivery_seq: std::sync::atomic::AtomicU64,
    /// In-memory index of sessions that currently hold >=1 buffered delivery.
    /// Lets the response hot path skip the blocking `list_prefix` KV scan (a
    /// `block_in_place` that parks a tokio worker) for the overwhelmingly
    /// common no-pending case. Authoritative: hydrated from KV at boot,
    /// inserted after a store, cleared (remove-first) on a drain.
    sessions_with_pending: dashmap::DashSet<String>,
}

impl std::fmt::Debug for KvBackedPipelineStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedPipelineStore")
            .field("pipeline_ttl", &self.pipeline_ttl)
            .field("delivery_ttl", &self.delivery_ttl)
            .field("pending_request_ttl", &self.pending_request_ttl)
            .finish()
    }
}

impl KvBackedPipelineStore {
    pub fn new(state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>) -> Self {
        // Hydrate the pending-delivery index (see field docs) so a drain after
        // a restart still finds buffered rows rather than trusting a cold set.
        let sessions_with_pending = dashmap::DashSet::new();
        if let Ok(entries) = Self::block(async { state.list_prefix("delivery:", 4096).await }) {
            for (key, _) in entries {
                if let Some((sid, _)) = key
                    .strip_prefix("delivery:")
                    .and_then(|rest| rest.split_once(':'))
                {
                    sessions_with_pending.insert(sid.to_owned());
                }
            }
        }
        Self {
            state,
            sessions_with_pending,
            pipeline_ttl: std::time::Duration::from_secs(300),
            // A buffered terminal delivery must outlive the suspend window it
            // belongs to: a client reconnecting late (legacy 2025-11-25 SSE)
            // drains its pending deliveries from KV, and if the delivery key
            // expired before the pipeline/pending-request key the terminal
            // result is silently lost. Kept >= pipeline/pending TTL so the
            // delivery is fetchable for the full lifetime of the pipeline that
            // produced it.
            delivery_ttl: std::time::Duration::from_secs(300),
            pending_request_ttl: std::time::Duration::from_secs(300),
            delivery_seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Convenience: in-process `MemoryKv` backing. Same use case as
    /// `KvBackedSessionStore::new_in_memory` — keeps test fixtures
    /// and single-node boot paths terse.
    pub fn new_in_memory() -> Self {
        Self::new(std::sync::Arc::new(
            crate::builtins::cluster_primitives::MemoryKv::new(),
        ))
    }

    fn pipeline_key(id: &str) -> String {
        format!("pipeline:{id}")
    }
    /// Per-version single-winner claim marker for [`try_claim_pipeline`].
    /// Distinct per `(pipeline, version)` so a later resume (which bumps
    /// the version) is never blocked by an earlier version's marker.
    fn pipeline_claim_key(id: &str, version: u64) -> String {
        format!("pipeline-claim:{id}:{version}")
    }
    fn pending_req_key(srv_req_id: &str) -> String {
        format!("pending_req:{srv_req_id}")
    }
    fn delivery_key(session_id: &str, delivery_id: &str) -> String {
        format!("delivery:{session_id}:{delivery_id}")
    }
    fn delivery_session_prefix(session_id: &str) -> String {
        format!("delivery:{session_id}:")
    }

    fn block<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        use tokio::runtime::{Handle, RuntimeFlavor};
        match Handle::try_current() {
            Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| h.block_on(fut))
            }
            _ => futures::executor::block_on(fut),
        }
    }
}

impl PipelineStore for KvBackedPipelineStore {
    fn save_pipeline(&self, state: &PipelineExecutionState) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(state)?;
        let key = Self::pipeline_key(&state.pipeline_id);
        Self::block(async {
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.pipeline_ttl))
                .await
        })
        .map_err(|e| anyhow::anyhow!("kv save_pipeline: {e}"))
    }

    fn load_pipeline(&self, pipeline_id: &str) -> anyhow::Result<Option<PipelineExecutionState>> {
        let key = Self::pipeline_key(pipeline_id);
        let value = Self::block(async { self.state.get(&key).await })
            .map_err(|e| anyhow::anyhow!("kv load_pipeline: {e}"))?;
        let Some(v) = value else { return Ok(None) };
        let state: PipelineExecutionState = serde_json::from_slice(&v.bytes)?;
        Ok(Some(state))
    }

    fn try_claim_pipeline(&self, pipeline_id: &str, expected_version: u64) -> anyhow::Result<bool> {
        // Atomic single-winner claim. The version check is a fast reject
        // for a stale claim, but the AUTHORITATIVE gate is an atomic
        // `put_if_absent` on a per-`(pipeline, version)` marker key: of N
        // replicas concurrently resuming the same suspended pipeline at
        // `expected_version`, exactly one wins the marker and proceeds to
        // bump the version — so the resumed steps execute once.
        let key = Self::pipeline_key(pipeline_id);
        let claim_key = Self::pipeline_claim_key(pipeline_id, expected_version);
        Self::block(async {
            let Some(value) = self.state.get(&key).await? else {
                return Ok(false);
            };
            let mut current: PipelineExecutionState = serde_json::from_slice(&value.bytes)
                .map_err(|e| mcpg_cluster_api::ClusterError::Internal {
                    reason: format!("decode pipeline `{pipeline_id}`: {e}"),
                })?;
            if current.state_version != expected_version {
                return Ok(false);
            }
            // Atomic claim of THIS version across replicas. The loser of
            // the race gets `false` here and does not bump the version.
            let won = self
                .state
                .put_if_absent(
                    &claim_key,
                    bytes::Bytes::from_static(b"1"),
                    Some(self.pipeline_ttl),
                )
                .await?;
            if !won {
                return Ok(false);
            }
            current.state_version += 1;
            let bytes = serde_json::to_vec(&current).map_err(|e| {
                mcpg_cluster_api::ClusterError::Internal {
                    reason: format!("encode pipeline `{pipeline_id}`: {e}"),
                }
            })?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.pipeline_ttl))
                .await?;
            Ok::<bool, mcpg_cluster_api::ClusterError>(true)
        })
        .map_err(|e| anyhow::anyhow!("kv try_claim_pipeline: {e}"))
    }

    fn set_original_jsonrpc_id_if_version(
        &self,
        pipeline_id: &str,
        expected_version: u64,
        original_jsonrpc_id: &Value,
    ) -> anyhow::Result<bool> {
        let key = Self::pipeline_key(pipeline_id);
        let id = original_jsonrpc_id.clone();
        Self::block(async {
            // Read the current row. Absent → reaped or already completed;
            // do NOT recreate it (the racy blind save this replaces could
            // resurrect a deleted pipeline).
            let Some(value) = self.state.get(&key).await? else {
                return Ok(false);
            };
            let mut current: PipelineExecutionState = serde_json::from_slice(&value.bytes)
                .map_err(|e| mcpg_cluster_api::ClusterError::Internal {
                    reason: format!("decode pipeline `{pipeline_id}`: {e}"),
                })?;
            // Version guard: a concurrent claim/resume has bumped the version
            // (and may have rewritten the row); refuse to clobber it.
            if current.state_version != expected_version {
                return Ok(false);
            }
            current.original_jsonrpc_id = id;
            let bytes = serde_json::to_vec(&current).map_err(|e| {
                mcpg_cluster_api::ClusterError::Internal {
                    reason: format!("encode pipeline `{pipeline_id}`: {e}"),
                }
            })?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.pipeline_ttl))
                .await?;
            Ok::<bool, mcpg_cluster_api::ClusterError>(true)
        })
        .map_err(|e| anyhow::anyhow!("kv set_original_jsonrpc_id: {e}"))
    }

    fn delete_pipeline(&self, pipeline_id: &str) -> anyhow::Result<()> {
        let key = Self::pipeline_key(pipeline_id);
        Self::block(async { self.state.delete(&key).await })
            .map_err(|e| anyhow::anyhow!("kv delete_pipeline: {e}"))?;
        Ok(())
    }

    fn save_pending_server_request(&self, request: &PendingServerRequest) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(request)?;
        let key = Self::pending_req_key(&request.server_request_id);
        Self::block(async {
            self.state
                .put(
                    &key,
                    bytes::Bytes::from(bytes),
                    Some(self.pending_request_ttl),
                )
                .await
        })
        .map_err(|e| anyhow::anyhow!("kv save_pending_server_request: {e}"))
    }

    fn load_pending_server_request(
        &self,
        server_request_id: &str,
    ) -> anyhow::Result<Option<PendingServerRequest>> {
        let key = Self::pending_req_key(server_request_id);
        let value = Self::block(async { self.state.get(&key).await })
            .map_err(|e| anyhow::anyhow!("kv load_pending_server_request: {e}"))?;
        let Some(v) = value else { return Ok(None) };
        let req: PendingServerRequest = serde_json::from_slice(&v.bytes)?;
        Ok(Some(req))
    }

    fn delete_pending_server_request(&self, server_request_id: &str) -> anyhow::Result<()> {
        let key = Self::pending_req_key(server_request_id);
        Self::block(async { self.state.delete(&key).await })
            .map_err(|e| anyhow::anyhow!("kv delete_pending_server_request: {e}"))?;
        Ok(())
    }

    fn store_pending_delivery(
        &self,
        session_id: &str,
        message: &DeliveryMessage,
    ) -> anyhow::Result<String> {
        // Prefix the delivery id with a per-store monotonic 20-digit
        // sequence so `list_prefix` returns deliveries in insertion
        // order. UUIDs alone sort randomly; a wall-clock timestamp
        // collides on same-millisecond bursts. The trailing UUID
        // keeps ids globally unique across replicas.
        let seq = self
            .delivery_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let delivery_id = format!("{seq:020}-{}", uuid::Uuid::new_v4());
        let bytes = serde_json::to_vec(message)?;
        let key = Self::delivery_key(session_id, &delivery_id);
        Self::block(async {
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.delivery_ttl))
                .await
        })
        .map_err(|e| anyhow::anyhow!("kv store_pending_delivery: {e}"))?;
        // Mark AFTER the put is durable so the index never claims a delivery
        // exists before it does.
        self.sessions_with_pending.insert(session_id.to_owned());
        Ok(delivery_id)
    }

    fn take_pending_deliveries(&self, session_id: &str) -> anyhow::Result<Vec<DeliveryMessage>> {
        // Remove-first gate: skip the blocking KV scan (a worker-parking
        // `block_in_place`) when this session has no buffered deliveries — the
        // common case on the tools/call hot path. Removing before the scan
        // keeps a concurrent `store_pending_delivery` (which re-inserts) from
        // being dropped.
        if self.sessions_with_pending.remove(session_id).is_none() {
            return Ok(Vec::new());
        }
        let prefix = Self::delivery_session_prefix(session_id);
        Self::block(async {
            // Sort by key — `store_pending_delivery` prefixes the
            // delivery id with a monotonic sequence so lex sort
            // recovers insertion order. `list_prefix` itself does
            // not promise an order (e.g. DashMap-backed `MemoryKv`
            // iterates by shard).
            let mut entries = self.state.list_prefix(&prefix, 1024).await?;
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let mut messages = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let mut msg: DeliveryMessage = match serde_json::from_slice(&value.bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                // Re-stamp the delivery id from the KV key so the SSE event
                // built from a drained backlog row carries the same id a live
                // delivery would — a reconnect can then ack/prune it.
                if let Some(delivery_id) = key.strip_prefix(&prefix) {
                    msg.delivery_id = delivery_id.to_owned();
                }
                messages.push(msg);
                let _ = self.state.delete(&key).await;
            }
            Ok::<Vec<DeliveryMessage>, mcpg_cluster_api::ClusterError>(messages)
        })
        .map_err(|e| anyhow::anyhow!("kv take_pending_deliveries: {e}"))
    }

    fn delete_delivery(&self, session_id: &str, delivery_id: &str) -> anyhow::Result<()> {
        if delivery_id.is_empty() {
            return Ok(());
        }
        let key = Self::delivery_key(session_id, delivery_id);
        Self::block(async { self.state.delete(&key).await })
            .map_err(|e| anyhow::anyhow!("kv delete_delivery: {e}"))?;
        Ok(())
    }

    fn list_expired_pipelines(&self) -> anyhow::Result<Vec<String>> {
        Self::block(async {
            let entries = self.state.list_prefix("pipeline:", 4096).await?;
            let now = Utc::now();
            let mut expired = Vec::new();
            for (_, value) in entries {
                if let Ok(state) = serde_json::from_slice::<PipelineExecutionState>(&value.bytes) {
                    let elapsed = (now - state.created_at).num_milliseconds() as u64;
                    if elapsed >= state.pipeline_timeout_ms {
                        expired.push(state.pipeline_id);
                    }
                }
            }
            Ok::<Vec<String>, mcpg_cluster_api::ClusterError>(expired)
        })
        .map_err(|e| anyhow::anyhow!("kv list_expired_pipelines: {e}"))
    }

    fn list_elicitation_timed_out(&self) -> anyhow::Result<Vec<(String, String, Value)>> {
        // The `pipeline-claim:` marker shares the `pipeline:` namespace only
        // by prefix accident — guard against decoding a claim marker as a
        // pipeline by relying on serde (a `b"1"` marker fails to decode).
        Self::block(async {
            let entries = self.state.list_prefix("pipeline:", 4096).await?;
            let now = Utc::now();
            let mut timed_out = Vec::new();
            for (_, value) in entries {
                let Ok(state) = serde_json::from_slice::<PipelineExecutionState>(&value.bytes)
                else {
                    continue;
                };
                let (Some(suspended_at), Some(elic_ms)) =
                    (state.suspended_at, state.elicitation_timeout_ms)
                else {
                    continue;
                };
                if elic_ms == 0 {
                    continue;
                }
                let elapsed = (now - suspended_at).num_milliseconds() as u64;
                if elapsed >= elic_ms {
                    timed_out.push((
                        state.pipeline_id,
                        state.session_id,
                        state.original_jsonrpc_id,
                    ));
                }
            }
            Ok::<Vec<(String, String, Value)>, mcpg_cluster_api::ClusterError>(timed_out)
        })
        .map_err(|e| anyhow::anyhow!("kv list_elicitation_timed_out: {e}"))
    }

    fn find_suspended_by_jsonrpc_id(
        &self,
        session_id: &str,
        original_jsonrpc_id: &str,
    ) -> anyhow::Result<Option<PipelineExecutionState>> {
        Self::block(async {
            let entries = self.state.list_prefix("pipeline:", 4096).await?;
            for (_, value) in entries {
                let Ok(state) = serde_json::from_slice::<PipelineExecutionState>(&value.bytes)
                else {
                    continue;
                };
                // The cancel `target_id` is the JSON-RPC id rendered to string
                // (`Value::to_string`); compare against the stored id rendered
                // the same way so a numeric / string id matches identically.
                let rendered = state.original_jsonrpc_id.to_string();
                if state.suspended_at.is_some()
                    && state.session_id == session_id
                    && rendered == original_jsonrpc_id
                {
                    return Ok(Some(state));
                }
            }
            Ok::<Option<PipelineExecutionState>, mcpg_cluster_api::ClusterError>(None)
        })
        .map_err(|e| anyhow::anyhow!("kv find_suspended_by_jsonrpc_id: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pipeline_state() -> PipelineExecutionState {
        PipelineExecutionState {
            pipeline_id: "pipe-1".to_owned(),
            session_id: "sess-1".to_owned(),
            original_jsonrpc_id: Value::Number(serde_json::Number::from(42)),
            tool_name: "test_tool".to_owned(),
            steps: vec![],
            current_step_index: 0,
            completed_steps: BTreeMap::new(),
            original_args: serde_json::json!({}),
            request_context: crate::runtime::RequestContext::new(
                crate::runtime::GatewayRequestId::new(),
                None,
                Some("sess-1".to_owned()),
                None,
                crate::runtime::RequestIdentity::Anonymous {
                    source: "test".to_owned(),
                },
                crate::runtime::TransportKind::Http,
            ),
            created_at: Utc::now(),
            suspended_at: None,
            pipeline_timeout_ms: 30_000,
            pending_server_request_id: None,
            elicitation_timeout_ms: None,
            related_task_id: None,
            client_capabilities: crate::protocol::ClientCapabilities::default(),
            state_version: 0,
            surface: PipelineSurface::Tool,
        }
    }

    #[test]
    fn pipeline_store_save_and_load() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state();
        store.save_pipeline(&state).unwrap();
        let loaded = store.load_pipeline("pipe-1").unwrap().unwrap();
        assert_eq!(loaded.pipeline_id, "pipe-1");
        assert_eq!(loaded.state_version, 0);
    }

    #[test]
    fn pipeline_store_cas_claim_succeeds() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state();
        store.save_pipeline(&state).unwrap();
        assert!(store.try_claim_pipeline("pipe-1", 0).unwrap());
        let loaded = store.load_pipeline("pipe-1").unwrap().unwrap();
        assert_eq!(loaded.state_version, 1);
    }

    #[test]
    fn pipeline_store_cas_claim_fails_on_version_mismatch() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state();
        store.save_pipeline(&state).unwrap();
        assert!(store.try_claim_pipeline("pipe-1", 0).unwrap());
        // Second claim with old version should fail
        assert!(!store.try_claim_pipeline("pipe-1", 0).unwrap());
    }

    #[test]
    fn pipeline_claim_blocked_by_existing_version_marker() {
        // The per-(pipeline, version) put_if_absent marker is the
        // authoritative single-winner gate, not just the version check.
        // Even when the version still matches, a claim loses if another
        // replica already holds the marker — and the loser must NOT bump
        // the version (no double-resume).
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state(); // state_version == 0
        store.save_pipeline(&state).unwrap();
        // Simulate replica B having already claimed version 0.
        futures::executor::block_on(store.state.put_if_absent(
            &KvBackedPipelineStore::pipeline_claim_key("pipe-1", 0),
            bytes::Bytes::from_static(b"1"),
            None,
        ))
        .unwrap();
        // Our claim at the matching version still loses to the marker.
        assert!(!store.try_claim_pipeline("pipe-1", 0).unwrap());
        // The version is untouched — the loser did not mutate the record.
        assert_eq!(
            store
                .load_pipeline("pipe-1")
                .unwrap()
                .unwrap()
                .state_version,
            0
        );
    }

    #[test]
    fn pipeline_store_delete_removes_state() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state();
        store.save_pipeline(&state).unwrap();
        store.delete_pipeline("pipe-1").unwrap();
        assert!(store.load_pipeline("pipe-1").unwrap().is_none());
    }

    #[test]
    fn set_original_jsonrpc_id_applies_at_matching_version() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state(); // state_version == 0
        store.save_pipeline(&state).unwrap();
        let id = Value::String("rpc-7".to_owned());
        assert!(
            store
                .set_original_jsonrpc_id_if_version("pipe-1", 0, &id)
                .unwrap()
        );
        let loaded = store.load_pipeline("pipe-1").unwrap().unwrap();
        assert_eq!(loaded.original_jsonrpc_id, id);
        // The patch leaves the version untouched so it can't interfere with
        // the resume-claim CAS.
        assert_eq!(loaded.state_version, 0);
    }

    #[test]
    fn set_original_jsonrpc_id_refuses_resurrecting_reaped_row() {
        let store = KvBackedPipelineStore::new_in_memory();
        // No row was ever saved (or it was reaped): the guarded patch must
        // NOT recreate it.
        let id = Value::String("rpc-7".to_owned());
        assert!(
            !store
                .set_original_jsonrpc_id_if_version("pipe-gone", 0, &id)
                .unwrap()
        );
        assert!(store.load_pipeline("pipe-gone").unwrap().is_none());
    }

    #[test]
    fn set_original_jsonrpc_id_refuses_clobbering_advanced_version() {
        let store = KvBackedPipelineStore::new_in_memory();
        let state = sample_pipeline_state(); // state_version == 0
        store.save_pipeline(&state).unwrap();
        // A concurrent claim/resume advanced the version (and may have
        // rewritten the row); the stale patch must not clobber it.
        assert!(store.try_claim_pipeline("pipe-1", 0).unwrap()); // -> version 1
        let id = Value::String("rpc-7".to_owned());
        assert!(
            !store
                .set_original_jsonrpc_id_if_version("pipe-1", 0, &id)
                .unwrap()
        );
        let loaded = store.load_pipeline("pipe-1").unwrap().unwrap();
        assert_eq!(loaded.state_version, 1);
        // The original id (from the fixture) is preserved, not overwritten.
        assert_eq!(
            loaded.original_jsonrpc_id,
            Value::Number(serde_json::Number::from(42))
        );
    }

    #[test]
    fn delivery_ttl_is_at_least_pipeline_ttl() {
        // A buffered terminal delivery must outlive the suspend window of the
        // pipeline that produced it, else a late legacy reconnect loses the
        // result (delivery key expired while the pipeline key was still live).
        let store = KvBackedPipelineStore::new_in_memory();
        assert!(store.delivery_ttl >= store.pipeline_ttl);
        assert!(store.delivery_ttl >= store.pending_request_ttl);
    }

    #[test]
    fn pending_server_request_round_trip() {
        let store = KvBackedPipelineStore::new_in_memory();
        let req = PendingServerRequest {
            server_request_id: "srv-req-1".to_owned(),
            pipeline_id: "pipe-1".to_owned(),
            session_id: "sess-1".to_owned(),
            step_id: "step_elicit".to_owned(),
            timeout_ms: 60_000,
            created_at: Utc::now(),
        };
        store.save_pending_server_request(&req).unwrap();
        let loaded = store
            .load_pending_server_request("srv-req-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.pipeline_id, "pipe-1");
        store.delete_pending_server_request("srv-req-1").unwrap();
        assert!(
            store
                .load_pending_server_request("srv-req-1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn pending_delivery_store_and_take() {
        let store = KvBackedPipelineStore::new_in_memory();
        let msg = DeliveryMessage {
            kind: DeliveryKind::ServerRequest,
            jsonrpc_message: serde_json::json!({"method": "elicitation/create"}),
            delivery_id: String::new(),
        };
        store.store_pending_delivery("sess-1", &msg).unwrap();
        store.store_pending_delivery("sess-1", &msg).unwrap();
        let taken = store.take_pending_deliveries("sess-1").unwrap();
        assert_eq!(taken.len(), 2);
        // Second take returns empty
        let taken2 = store.take_pending_deliveries("sess-1").unwrap();
        assert!(taken2.is_empty());
    }

    #[test]
    fn take_pending_deliveries_stamps_delivery_id_from_key() {
        // The drained copy must carry the id it is stored under, so the SSE
        // event built from it can be tagged for a later reconnect ack.
        let store = KvBackedPipelineStore::new_in_memory();
        let msg = DeliveryMessage {
            kind: DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}}),
            delivery_id: String::new(),
        };
        let assigned = store.store_pending_delivery("sess-1", &msg).unwrap();
        let taken = store.take_pending_deliveries("sess-1").unwrap();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].delivery_id, assigned);
    }

    #[test]
    fn delete_delivery_prunes_acked_row_only() {
        // Reconnect ack-prune: deleting the exact acknowledged row
        // removes it from the backlog so a subsequent drain does not replay
        // it — while a non-acked row is left intact (no lost delivery).
        let store = KvBackedPipelineStore::new_in_memory();
        let terminal = DeliveryMessage {
            kind: DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}}),
            delivery_id: String::new(),
        };
        let other = DeliveryMessage {
            kind: DeliveryKind::ServerRequest,
            jsonrpc_message: serde_json::json!({"method":"elicitation/create"}),
            delivery_id: String::new(),
        };
        let acked = store.store_pending_delivery("sess-1", &terminal).unwrap();
        let _kept = store.store_pending_delivery("sess-1", &other).unwrap();

        // Client reconnects having received the terminal result live → prune it.
        store.delete_delivery("sess-1", &acked).unwrap();

        let taken = store.take_pending_deliveries("sess-1").unwrap();
        // The acked terminal result is NOT replayed; the un-acked row remains.
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].kind, DeliveryKind::ServerRequest);
    }

    #[test]
    fn delete_delivery_is_noop_for_empty_or_missing_id() {
        let store = KvBackedPipelineStore::new_in_memory();
        // Empty id and unknown id are both no-ops (never an error).
        store.delete_delivery("sess-1", "").unwrap();
        store
            .delete_delivery("sess-1", "00000000000000000000-deadbeef")
            .unwrap();
    }

    #[test]
    fn delivery_message_delivery_id_is_not_wire_visible_when_empty() {
        // The internal book-keeping id must not appear in the serialized
        // delivery when empty (backward-compatible with pre-existing rows).
        let msg = DeliveryMessage {
            kind: DeliveryKind::DeferredToolResult,
            jsonrpc_message: serde_json::json!({"x":1}),
            delivery_id: String::new(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("delivery_id"));
        // And a legacy row without the field still decodes.
        let legacy = r#"{"kind":"DeferredToolResult","jsonrpc_message":{"x":1}}"#;
        let decoded: DeliveryMessage = serde_json::from_str(legacy).unwrap();
        assert!(decoded.delivery_id.is_empty());
    }

    #[test]
    fn pipeline_state_serialization_round_trip() {
        let state = sample_pipeline_state();
        let json = serde_json::to_string(&state).unwrap();
        let restored: PipelineExecutionState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pipeline_id, state.pipeline_id);
        assert_eq!(restored.session_id, state.session_id);
        assert_eq!(restored.state_version, state.state_version);
    }

    #[test]
    fn list_expired_pipelines_returns_timed_out() {
        let store = KvBackedPipelineStore::new_in_memory();
        let mut state = sample_pipeline_state();
        state.pipeline_timeout_ms = 0; // immediately expired
        store.save_pipeline(&state).unwrap();
        let expired = store.list_expired_pipelines().unwrap();
        assert_eq!(expired, vec!["pipe-1"]);
    }

    #[test]
    fn list_elicitation_timed_out_only_returns_overdue_suspended() {
        let store = KvBackedPipelineStore::new_in_memory();
        // Suspended, elicitation bound elapsed.
        let mut overdue = sample_pipeline_state();
        overdue.pipeline_id = "pipe-overdue".to_owned();
        overdue.pipeline_timeout_ms = 999_999_999;
        overdue.suspended_at = Some(Utc::now() - chrono::Duration::seconds(5));
        overdue.elicitation_timeout_ms = Some(1);
        store.save_pipeline(&overdue).unwrap();
        // Suspended, elicitation bound NOT elapsed.
        let mut fresh = sample_pipeline_state();
        fresh.pipeline_id = "pipe-fresh".to_owned();
        fresh.suspended_at = Some(Utc::now());
        fresh.elicitation_timeout_ms = Some(600_000);
        store.save_pipeline(&fresh).unwrap();
        // Not suspended.
        let mut running = sample_pipeline_state();
        running.pipeline_id = "pipe-running".to_owned();
        store.save_pipeline(&running).unwrap();

        let timed_out = store.list_elicitation_timed_out().unwrap();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].0, "pipe-overdue");
        assert_eq!(timed_out[0].1, "sess-1");
    }

    #[test]
    fn find_suspended_by_jsonrpc_id_matches_session_and_id() {
        let store = KvBackedPipelineStore::new_in_memory();
        let mut suspended = sample_pipeline_state();
        suspended.suspended_at = Some(Utc::now());
        // original_jsonrpc_id is Number(42) in the sample.
        store.save_pipeline(&suspended).unwrap();

        // Match by rendered id + session.
        let found = store.find_suspended_by_jsonrpc_id("sess-1", "42").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().pipeline_id, "pipe-1");

        // Wrong session → no match.
        assert!(
            store
                .find_suspended_by_jsonrpc_id("other-sess", "42")
                .unwrap()
                .is_none()
        );
        // Wrong id → no match.
        assert!(
            store
                .find_suspended_by_jsonrpc_id("sess-1", "99")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn find_suspended_by_jsonrpc_id_ignores_running_pipelines() {
        let store = KvBackedPipelineStore::new_in_memory();
        let running = sample_pipeline_state(); // suspended_at == None
        store.save_pipeline(&running).unwrap();
        assert!(
            store
                .find_suspended_by_jsonrpc_id("sess-1", "42")
                .unwrap()
                .is_none()
        );
    }
}
