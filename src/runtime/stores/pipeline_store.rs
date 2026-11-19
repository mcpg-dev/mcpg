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
/// the client answers its input requests.
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
    /// persists the terminal envelope on the task, and the reaper fails the
    /// task of a suspended pipeline it reaps.
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

/// A notification routed through the delivery bus to a session's streams
/// (`subscriptions/listen`, a request's own response stream), or kept in
/// the session's backlog until the request that produced it drains it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryMessage {
    pub kind: DeliveryKind,
    pub jsonrpc_message: Value,
}

/// Discriminant for the type of delivery message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeliveryKind {
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

    /// Store a notification in a session's backlog, in delivery order.
    fn store_pending_delivery(
        &self,
        session_id: &str,
        message: &DeliveryMessage,
    ) -> anyhow::Result<()>;

    /// Load and delete all pending deliveries for a session, in the order
    /// they were stored.
    fn take_pending_deliveries(&self, session_id: &str) -> anyhow::Result<Vec<DeliveryMessage>>;

    /// The pipelines that have exceeded their whole-pipeline timeout.
    fn list_expired_pipelines(&self) -> anyhow::Result<Vec<PipelineExecutionState>>;

    /// The pipelines SUSPENDED past their per-step `elicitation_timeout_ms`
    /// (measured from `suspended_at`), distinct from the whole-pipeline
    /// `pipeline_timeout_ms` sweep.
    fn list_elicitation_timed_out(&self) -> anyhow::Result<Vec<PipelineExecutionState>>;

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
    /// TTL applied to buffered deliveries: as long as the pipeline that
    /// produced them may run.
    delivery_ttl: std::time::Duration,
    pending_request_ttl: std::time::Duration,
    /// In-memory index of sessions that currently hold >=1 buffered delivery,
    /// with the time of each one's last store. Lets the response hot path
    /// skip the blocking `list_prefix` KV scan (a `block_in_place` that parks
    /// a tokio worker) for the overwhelmingly common no-pending case.
    /// Hydrated from KV at boot, set after a store, cleared (remove-first)
    /// on a drain. A request drains the deliveries its own work stored on
    /// this replica. An entry whose last store is older than `delivery_ttl`
    /// names no live row, so it is pruned.
    sessions_with_pending: dashmap::DashMap<String, std::time::Instant>,
    /// When `sessions_with_pending` was last pruned.
    last_pending_prune: parking_lot::Mutex<std::time::Instant>,
}

/// How often a store prunes the pending-delivery index at most.
const PENDING_PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

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
        let sessions_with_pending = dashmap::DashMap::new();
        let now = std::time::Instant::now();
        if let Ok(entries) = Self::block(async { state.list_prefix("delivery:", 4096).await }) {
            for (key, _) in entries {
                if let Some((sid, _)) = key
                    .strip_prefix("delivery:")
                    .and_then(|rest| rest.split_once(':'))
                {
                    sessions_with_pending.insert(sid.to_owned(), now);
                }
            }
        }
        Self {
            state,
            sessions_with_pending,
            last_pending_prune: parking_lot::Mutex::new(now),
            pipeline_ttl: std::time::Duration::from_secs(300),
            delivery_ttl: std::time::Duration::from_secs(300),
            pending_request_ttl: std::time::Duration::from_secs(300),
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
    /// The suspended pipeline a session's JSON-RPC id (rendered with
    /// `Value::to_string`) belongs to: a key per suspension, holding the
    /// pipeline id, living as long as a pipeline. Both parts are encoded,
    /// so no key starts another's.
    fn suspended_rpc_key(session_id: &str, rendered_rpc_id: &str) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "pipeline-rpc:{}:{}",
            b64.encode(session_id),
            b64.encode(rendered_rpc_id)
        )
    }

    /// Every pipeline in the store.
    async fn all_pipelines(
        &self,
    ) -> Result<Vec<PipelineExecutionState>, mcpg_cluster_api::ClusterError> {
        Ok(mcpg_cluster_api::list_all(&*self.state, "pipeline:")
            .await?
            .into_iter()
            .filter_map(|(_, value)| {
                serde_json::from_slice::<PipelineExecutionState>(&value.bytes).ok()
            })
            .collect())
    }
    fn delivery_key(session_id: &str, delivery_id: &str) -> String {
        format!("delivery:{session_id}:{delivery_id}")
    }
    fn delivery_session_prefix(session_id: &str) -> String {
        format!("delivery:{session_id}:")
    }
    /// Per-session atomic sequence counter behind every delivery id.
    /// Deliberately OUTSIDE the `delivery:` namespace so backlog listings
    /// (drains, the boot-time pending-index hydrate) never decode it as a
    /// row.
    fn delivery_seq_key(session_id: &str) -> String {
        format!("delivery-seq:{session_id}")
    }

    fn block<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        super::block_on_store(fut)
    }

    /// Drop the index entries whose rows have all expired: the last store
    /// of each was longer ago than `delivery_ttl`, the TTL of every row. A
    /// store that races the prune sets a fresh time, so its entry stays.
    /// Runs at most once per [`PENDING_PRUNE_INTERVAL`].
    fn prune_pending_index(&self) {
        {
            let Some(mut last) = self.last_pending_prune.try_lock() else {
                return;
            };
            if last.elapsed() < PENDING_PRUNE_INTERVAL {
                return;
            }
            *last = std::time::Instant::now();
        }
        let ttl = self.delivery_ttl;
        self.sessions_with_pending
            .retain(|_, stored_at| stored_at.elapsed() < ttl);
    }

    /// Sessions the pending-delivery index names.
    #[cfg(test)]
    pub(crate) fn sessions_with_pending(&self) -> usize {
        self.sessions_with_pending.len()
    }

    /// Read, decode, delete and return the session's buffered deliveries in
    /// sequence order.
    fn drain_pending_deliveries(&self, session_id: &str) -> anyhow::Result<Vec<DeliveryMessage>> {
        let prefix = Self::delivery_session_prefix(session_id);
        Self::block(async {
            // Sort by key — `store_pending_delivery` prefixes the
            // delivery id with a monotonic sequence so lex sort
            // recovers delivery order. `list_prefix` itself does
            // not promise an order (e.g. DashMap-backed `MemoryKv`
            // iterates by shard).
            let mut entries = self.state.list_prefix(&prefix, 1024).await?;
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let mut messages = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let msg: DeliveryMessage = match serde_json::from_slice(&value.bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                messages.push(msg);
                let _ = self.state.delete(&key).await;
            }
            Ok::<Vec<DeliveryMessage>, mcpg_cluster_api::ClusterError>(messages)
        })
        .map_err(|e| anyhow::anyhow!("kv take_pending_deliveries: {e}"))
    }
}

impl PipelineStore for KvBackedPipelineStore {
    fn save_pipeline(&self, state: &PipelineExecutionState) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(state)?;
        let key = Self::pipeline_key(&state.pipeline_id);
        Self::block(async {
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.pipeline_ttl))
                .await?;
            // Found by its JSON-RPC id while suspended; the lookup checks
            // the pipeline itself, so the key needs no removal on resume.
            if state.suspended_at.is_some() {
                let rpc_key = Self::suspended_rpc_key(
                    &state.session_id,
                    &state.original_jsonrpc_id.to_string(),
                );
                self.state
                    .put(
                        &rpc_key,
                        bytes::Bytes::from(state.pipeline_id.clone()),
                        Some(self.pipeline_ttl),
                    )
                    .await?;
            }
            Ok::<(), mcpg_cluster_api::ClusterError>(())
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
            if current.suspended_at.is_some() {
                let rpc_key = Self::suspended_rpc_key(
                    &current.session_id,
                    &current.original_jsonrpc_id.to_string(),
                );
                self.state
                    .put(
                        &rpc_key,
                        bytes::Bytes::from(current.pipeline_id.clone()),
                        Some(self.pipeline_ttl),
                    )
                    .await?;
            }
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
    ) -> anyhow::Result<()> {
        // Prefix the delivery id with a coordinator-monotonic 20-digit
        // per-session sequence so `list_prefix` returns a session's
        // deliveries in delivery order on EVERY replica — the atomic
        // `incr` makes interleaved stores from different replicas
        // globally ordered. UUIDs alone sort randomly; a wall-clock
        // timestamp collides on same-millisecond bursts. The trailing
        // UUID keeps ids globally unique.
        let bytes = serde_json::to_vec(message)?;
        let seq_key = Self::delivery_seq_key(session_id);
        Self::block(async {
            let seq = self
                .state
                .incr(&seq_key, 1, Some(self.delivery_ttl))
                .await?;
            let delivery_id = format!("{seq:020}-{}", uuid::Uuid::new_v4());
            let key = Self::delivery_key(session_id, &delivery_id);
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(self.delivery_ttl))
                .await
        })
        .map_err(|e| anyhow::anyhow!("kv store_pending_delivery: {e}"))?;
        // Mark AFTER the put is durable so the index never claims a delivery
        // exists before it does.
        self.sessions_with_pending
            .insert(session_id.to_owned(), std::time::Instant::now());
        self.prune_pending_index();
        Ok(())
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
        self.drain_pending_deliveries(session_id)
    }

    fn list_expired_pipelines(&self) -> anyhow::Result<Vec<PipelineExecutionState>> {
        Self::block(async {
            let now = Utc::now();
            let mut expired = Vec::new();
            for state in self.all_pipelines().await? {
                let elapsed = (now - state.created_at).num_milliseconds() as u64;
                if elapsed >= state.pipeline_timeout_ms {
                    expired.push(state);
                }
            }
            Ok::<Vec<PipelineExecutionState>, mcpg_cluster_api::ClusterError>(expired)
        })
        .map_err(|e| anyhow::anyhow!("kv list_expired_pipelines: {e}"))
    }

    fn list_elicitation_timed_out(&self) -> anyhow::Result<Vec<PipelineExecutionState>> {
        Self::block(async {
            let now = Utc::now();
            let mut timed_out = Vec::new();
            for state in self.all_pipelines().await? {
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
                    timed_out.push(state);
                }
            }
            Ok::<Vec<PipelineExecutionState>, mcpg_cluster_api::ClusterError>(timed_out)
        })
        .map_err(|e| anyhow::anyhow!("kv list_elicitation_timed_out: {e}"))
    }

    fn find_suspended_by_jsonrpc_id(
        &self,
        session_id: &str,
        original_jsonrpc_id: &str,
    ) -> anyhow::Result<Option<PipelineExecutionState>> {
        // The cancel `target_id` is the JSON-RPC id rendered to string
        // (`Value::to_string`); the key was written with the stored id
        // rendered the same way, so a numeric / string id matches
        // identically. The pipeline itself is checked: the key outlives a
        // resume.
        let rpc_key = Self::suspended_rpc_key(session_id, original_jsonrpc_id);
        Self::block(async {
            let Some(pointer) = self.state.get(&rpc_key).await? else {
                return Ok(None);
            };
            let pipeline_id = String::from_utf8_lossy(&pointer.bytes).into_owned();
            let Some(value) = self.state.get(&Self::pipeline_key(&pipeline_id)).await? else {
                return Ok(None);
            };
            let Ok(state) = serde_json::from_slice::<PipelineExecutionState>(&value.bytes) else {
                return Ok(None);
            };
            let rendered = state.original_jsonrpc_id.to_string();
            let matches = state.suspended_at.is_some()
                && state.session_id == session_id
                && rendered == original_jsonrpc_id;
            Ok::<Option<PipelineExecutionState>, mcpg_cluster_api::ClusterError>(
                matches.then_some(state),
            )
        })
        .map_err(|e| anyhow::anyhow!("kv find_suspended_by_jsonrpc_id: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pipeline_state() -> PipelineExecutionState {
        let mut request_context = crate::runtime::RequestContext::new(
            crate::runtime::GatewayRequestId::new(),
            None,
            crate::runtime::RequestIdentity::Anonymous {
                source: "test".to_owned(),
            },
            crate::runtime::TransportKind::Http,
        );
        request_context.session_id = Some("sess-1".to_owned());
        PipelineExecutionState {
            pipeline_id: "pipe-1".to_owned(),
            session_id: "sess-1".to_owned(),
            original_jsonrpc_id: Value::Number(serde_json::Number::from(42)),
            tool_name: "test_tool".to_owned(),
            steps: vec![],
            current_step_index: 0,
            completed_steps: BTreeMap::new(),
            original_args: serde_json::json!({}),
            request_context,
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
        // A buffered delivery lives as long as the pipeline that produced it
        // may run.
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
            kind: DeliveryKind::ProgressNotification,
            jsonrpc_message: serde_json::json!({"method": "notifications/progress"}),
        };
        store.store_pending_delivery("sess-1", &msg).unwrap();
        store.store_pending_delivery("sess-1", &msg).unwrap();
        let taken = store.take_pending_deliveries("sess-1").unwrap();
        assert_eq!(taken.len(), 2);
        // Second take returns empty
        let taken2 = store.take_pending_deliveries("sess-1").unwrap();
        assert!(taken2.is_empty());
    }

    /// A session whose deliveries all expired leaves the index at the next
    /// prune, so sessions nobody drains do not grow it.
    #[test]
    fn the_pending_index_forgets_sessions_whose_rows_expired() {
        let mut store = KvBackedPipelineStore::new_in_memory();
        store.delivery_ttl = std::time::Duration::from_millis(20);
        let msg = DeliveryMessage {
            kind: DeliveryKind::Notification,
            jsonrpc_message: serde_json::json!({"method": "notifications/message"}),
        };
        for session in ["gone-1", "gone-2", "gone-3"] {
            store.store_pending_delivery(session, &msg).unwrap();
        }
        assert_eq!(store.sessions_with_pending(), 3);
        std::thread::sleep(std::time::Duration::from_millis(40));
        if let Some(due) = std::time::Instant::now().checked_sub(PENDING_PRUNE_INTERVAL) {
            *store.last_pending_prune.lock() = due;
        }
        store.store_pending_delivery("live", &msg).unwrap();
        assert_eq!(
            store.sessions_with_pending(),
            1,
            "only the session stored to now stays"
        );
        assert_eq!(store.take_pending_deliveries("live").unwrap().len(), 1);
    }

    fn delivery(kind: DeliveryKind, marker: u64) -> DeliveryMessage {
        DeliveryMessage {
            kind,
            jsonrpc_message: serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": { "marker": marker }
            }),
        }
    }

    fn markers(drained: &[DeliveryMessage]) -> Vec<u64> {
        drained
            .iter()
            .map(|m| m.jsonrpc_message["params"]["marker"].as_u64().unwrap())
            .collect()
    }

    /// Two stores sharing one coordinator KV = two replicas.
    fn replica_pair() -> (KvBackedPipelineStore, KvBackedPipelineStore) {
        let shared: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        (
            KvBackedPipelineStore::new(std::sync::Arc::clone(&shared)),
            KvBackedPipelineStore::new(shared),
        )
    }

    #[test]
    fn delivery_order_holds_across_replicas() {
        // Interleaved stores from two replicas sharing one coordinator KV
        // mint globally increasing per-session sequences, so the key-sorted
        // drain recovers true delivery order on ANY replica.
        let (a, b) = replica_pair();
        for marker in 0..6u64 {
            let store = if marker % 2 == 0 { &a } else { &b };
            store
                .store_pending_delivery("sess-x", &delivery(DeliveryKind::Notification, marker))
                .unwrap();
        }
        let drained = b.take_pending_deliveries("sess-x").unwrap();
        assert_eq!(markers(&drained), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_single_store_drains_in_insertion_order() {
        let store = KvBackedPipelineStore::new_in_memory();
        for marker in 0..4u64 {
            store
                .store_pending_delivery("sess-1", &delivery(DeliveryKind::Notification, marker))
                .unwrap();
        }
        let drained = store.take_pending_deliveries("sess-1").unwrap();
        assert_eq!(markers(&drained), vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_delivery_row_with_an_extra_field_decodes() {
        // Rows on the shared KV and bus may carry fields this replica does
        // not know.
        let row = r#"{"kind":"Notification","jsonrpc_message":{"x":1},"delivery_id":"7"}"#;
        let decoded: DeliveryMessage = serde_json::from_str(row).unwrap();
        assert_eq!(decoded.jsonrpc_message, serde_json::json!({"x": 1}));
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
        let ids: Vec<&str> = expired.iter().map(|s| s.pipeline_id.as_str()).collect();
        assert_eq!(ids, vec!["pipe-1"]);
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
        assert_eq!(timed_out[0].pipeline_id, "pipe-overdue");
        assert_eq!(timed_out[0].session_id, "sess-1");
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

    #[test]
    fn a_resumed_pipeline_is_no_longer_found_by_its_jsonrpc_id() {
        let store = KvBackedPipelineStore::new_in_memory();
        let mut state = sample_pipeline_state();
        state.suspended_at = Some(Utc::now());
        store.save_pipeline(&state).unwrap();
        state.suspended_at = None;
        store.save_pipeline(&state).unwrap();
        assert!(
            store
                .find_suspended_by_jsonrpc_id("sess-1", "42")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_new_jsonrpc_id_finds_the_suspended_pipeline() {
        let store = KvBackedPipelineStore::new_in_memory();
        let mut state = sample_pipeline_state();
        state.suspended_at = Some(Utc::now());
        store.save_pipeline(&state).unwrap();
        assert!(
            store
                .set_original_jsonrpc_id_if_version(
                    &state.pipeline_id,
                    0,
                    &serde_json::json!("r-7")
                )
                .unwrap()
        );
        let found = store
            .find_suspended_by_jsonrpc_id("sess-1", "\"r-7\"")
            .unwrap()
            .expect("found by the new id");
        assert_eq!(found.pipeline_id, "pipe-1");
        assert!(
            store
                .find_suspended_by_jsonrpc_id("sess-1", "42")
                .unwrap()
                .is_none(),
            "the old id no longer matches"
        );
    }

    /// More pipelines than one listing page of the old 4096 cap: a lookup
    /// and both sweeps still see every pipeline.
    #[test]
    fn lookups_and_sweeps_see_every_pipeline_of_a_large_store() {
        let store = KvBackedPipelineStore::new_in_memory();
        for i in 0..5_000 {
            let mut state = sample_pipeline_state();
            state.pipeline_id = format!("pipe-{i:05}");
            state.session_id = format!("sess-{i:05}");
            state.original_jsonrpc_id = serde_json::json!(i);
            state.pipeline_timeout_ms = 999_999_999;
            if i % 1_000 == 999 {
                state.suspended_at = Some(Utc::now() - chrono::Duration::seconds(5));
                state.elicitation_timeout_ms = Some(1);
            }
            store.save_pipeline(&state).unwrap();
        }
        let mut overdue = sample_pipeline_state();
        overdue.pipeline_id = "pipe-overdue".to_owned();
        overdue.pipeline_timeout_ms = 0;
        store.save_pipeline(&overdue).unwrap();

        let found = store
            .find_suspended_by_jsonrpc_id("sess-04999", "4999")
            .unwrap()
            .expect("the last suspended pipeline is found");
        assert_eq!(found.pipeline_id, "pipe-04999");
        assert_eq!(store.list_elicitation_timed_out().unwrap().len(), 5);
        let expired: Vec<String> = store
            .list_expired_pipelines()
            .unwrap()
            .into_iter()
            .map(|state| state.pipeline_id)
            .collect();
        assert_eq!(expired, vec!["pipe-overdue"]);
    }
}
