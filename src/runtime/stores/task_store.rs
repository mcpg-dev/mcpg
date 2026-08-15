//! Task store — persistent storage for MCP 2025-11-25 tasks.
//!
//! All backends go through `KvBackedTaskStore` over an
//! `Arc<dyn KeyValueStore>`. Single-node deployments use `MemoryKv`;
//! clustered deployments use the cluster plugin's primitives (redis,
//! nats, …).
//!
//! Task authorization binding: tasks are scoped to an owner key — the
//! caller's authorization context, passed as the `session_id`
//! parameter on every accessor. Only the owning caller can
//! query/cancel/retrieve a task; the gate is an exact-string compare.
//!
//! The owner key is caller-chosen. The modern (2026-07-28) wire binds
//! it to the request **principal** (`RequestContext::task_owner_key`)
//! so a task created on one cluster replica is pollable from another
//! via `tasks/get` (the principal is identical everywhere; the
//! per-replica synthetic session is not). The legacy (2025-11-25) wire
//! passes the session id, which is its authorization context.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::protocol::{JsonRpcErrorBody, Task, TaskStatus};

/// Default poll interval recommended to clients (milliseconds).
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 2000;

/// Retention + quota policy threaded through every backend.
#[derive(Debug, Clone, Copy)]
pub struct TaskRetentionPolicy {
    /// TTL applied when the client does not pass an explicit `task.ttl`.
    pub default_ttl_ms: u64,
    /// Maximum concurrent tasks per session (`0` disables the quota).
    pub max_tasks_per_session: usize,
    /// Upper bound on a single `tasks/result` HTTP blocking wait.
    /// Clients that need longer-running tasks reconnect via
    /// GET SSE + `Last-Event-Id` until the task goes terminal.
    pub result_wait_ms: u64,
}

impl Default for TaskRetentionPolicy {
    fn default() -> Self {
        Self {
            default_ttl_ms: 1_800_000, // 30 minutes
            max_tasks_per_session: 256,
            result_wait_ms: 30_000,
        }
    }
}

/// Terminal envelope for a task — the exact JSON-RPC response body the wrapped
/// request would have produced.
///
/// MCP 2025-11-25 requires `tasks/result` to return exactly what the underlying
/// request would have returned. Persisting the request-level payload (e.g. the
/// `ToolCallResult`) is not enough — we need to replay whichever of the two
/// JSON-RPC response shapes the original request would have taken, preserving
/// JSON-RPC errors with their code/message/data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalEnvelope {
    /// Successful JSON-RPC response: the embedded value is the `result` field
    /// the original request would have placed on a `JsonRpcSuccess`. For
    /// task-augmented `tools/call` this is the serialized `ToolCallResult`,
    /// including any `isError: true` tool-execution failures (those remain
    /// successful JSON-RPC responses per the tools spec).
    Success { result: Value },
    /// JSON-RPC error response: the full error body (`code`, `message`, `data`).
    Error { error: JsonRpcErrorBody },
}

impl TerminalEnvelope {
    pub fn success(result: Value) -> Self {
        TerminalEnvelope::Success { result }
    }

    pub fn error(error: JsonRpcErrorBody) -> Self {
        TerminalEnvelope::Error { error }
    }

    pub fn cancelled(reason: Option<String>) -> Self {
        // -32800 is the JSON-RPC-standard "request cancelled" code used by
        // MCP for client-cancelled operations.
        TerminalEnvelope::Error {
            error: JsonRpcErrorBody {
                code: -32800,
                message: reason.unwrap_or_else(|| "Task cancelled".to_owned()),
                data: None,
            },
        }
    }
}

/// Internal task record stored in the task store. Contains both public `Task`
/// metadata and internal bookkeeping (session binding, terminal envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    /// MCP task metadata (public).
    pub task: Task,
    /// Session ID that owns this task (authorization binding).
    pub session_id: String,
    /// The original JSON-RPC request ID from the tools/call that spawned this task.
    pub original_request_id: Value,
    /// Tool name being invoked.
    pub tool_name: String,
    /// Internal creation timestamp for TTL computation.
    pub created_at_utc: DateTime<Utc>,
    /// Terminal envelope, present once the task reaches any terminal state
    /// (Completed, Failed, or Cancelled). Drives `tasks/result` replay.
    pub terminal_envelope: Option<TerminalEnvelope>,
    /// MRTR resume handle for an `input_required` task. The same
    /// opaque, principal-bound `requestState` blob the inline
    /// `InputRequiredResult` carries; a `tasks/update` feeds the
    /// client's `inputResponses` back through this to resume the
    /// suspended pipeline. `None` while the task is not awaiting
    /// input. (SEP-2663 final + the MRTR fusion.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_state: Option<String>,
    /// Outstanding server→client requests for an `input_required`
    /// task, serialized as the SEP-2322 `inputRequests` map. Surfaced
    /// on `tasks/get`. `None` while the task is not awaiting input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_requests: Option<Value>,
}

/// Error type for task store operations.
#[derive(Debug, Clone)]
pub enum TaskStoreError {
    /// Task not found (or expired).
    NotFound,
    /// Task belongs to a different session.
    Forbidden,
    /// Task is not in a terminal state (for result retrieval).
    NotCompleted,
    /// The task has already reached a terminal state; the requested
    /// mutation would break MCP's "terminal tasks stay terminal" rule.
    /// Used for `tasks/cancel` on completed/failed/cancelled tasks and for
    /// any attempt to rewind a terminal status.
    AlreadyTerminal,
    /// The session already owns the maximum number of concurrent tasks.
    QuotaExceeded { limit: usize },
    /// Internal store error.
    Internal(String),
}

impl std::fmt::Display for TaskStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStoreError::NotFound => write!(f, "task not found"),
            TaskStoreError::Forbidden => write!(f, "task access forbidden"),
            TaskStoreError::NotCompleted => write!(f, "task not yet completed"),
            TaskStoreError::AlreadyTerminal => {
                write!(f, "task has already reached a terminal state")
            }
            TaskStoreError::QuotaExceeded { limit } => write!(
                f,
                "session already owns the maximum concurrent tasks ({limit})"
            ),
            TaskStoreError::Internal(msg) => write!(f, "task store error: {msg}"),
        }
    }
}

fn is_terminal_status(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

/// Trait for task storage backends. All methods are synchronous (matching
/// the `SessionStore` and `PipelineStore` patterns). Implementations must
/// be Send + Sync for use behind `Arc<dyn TaskStore>`.
pub trait TaskStore: Send + Sync + std::fmt::Debug {
    /// Active retention / quota policy for this store.
    fn retention_policy(&self) -> TaskRetentionPolicy;

    /// Create a new task record. Returns the full `TaskRecord` or
    /// `QuotaExceeded` when the session is already at the configured cap.
    fn create_task(
        &self,
        session_id: &str,
        original_request_id: Value,
        tool_name: &str,
        ttl_ms: Option<u64>,
    ) -> Result<TaskRecord, TaskStoreError>;

    /// Get a task by ID, with session authorization check.
    fn get_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;

    /// Update a non-terminal task's status and optional status message.
    ///
    /// MCP 2025-11-25 requires terminal tasks to stay terminal. Implementations
    /// MUST return [`TaskStoreError::AlreadyTerminal`] if the task has already
    /// reached Completed, Failed, or Cancelled.
    ///
    /// Ownership: implementations MUST return
    /// [`TaskStoreError::Forbidden`] — **before** mutating — when
    /// `session_id` does not match the task's owning session, so one
    /// session cannot tamper with another's task.
    fn update_task_status(
        &self,
        task_id: &str,
        session_id: &str,
        status: TaskStatus,
        status_message: Option<String>,
    ) -> Result<(), TaskStoreError>;

    /// Update a non-terminal task's `pollInterval` hint. SEP-2663
    /// `updateTask` carries this as a separate field from status —
    /// modern servers patch it when they want clients to back off
    /// or speed up between `getTask` calls.
    ///
    /// The default implementation is a no-op so external `TaskStore`
    /// impls that haven't been updated keep compiling; the in-memory
    /// store overrides it. Returns `AlreadyTerminal` if the task
    /// reached a terminal state — `pollInterval` is meaningless
    /// after termination.
    ///
    /// Ownership: implementations MUST return
    /// [`TaskStoreError::Forbidden`] — **before** mutating — when
    /// `session_id` does not match the task's owning session.
    fn set_task_poll_interval(
        &self,
        _task_id: &str,
        _session_id: &str,
        _poll_interval_ms: Option<u64>,
    ) -> Result<(), TaskStoreError> {
        Ok(())
    }

    /// Mark a non-terminal task as awaiting client input and record
    /// the MRTR resume handle (`request_state`) + the outstanding
    /// `input_requests` map. Surfaced on the next `tasks/get`; a
    /// `tasks/update` then feeds answers back through the resume
    /// codec. No-op default so external `TaskStore` impls keep
    /// compiling; the in-memory store overrides it.
    ///
    /// Ownership: implementations MUST return
    /// [`TaskStoreError::Forbidden`] — **before** mutating — when
    /// `session_id` does not match the task's owner key.
    fn set_task_awaiting_input(
        &self,
        _task_id: &str,
        _session_id: &str,
        _request_state: String,
        _input_requests: Value,
    ) -> Result<(), TaskStoreError> {
        Ok(())
    }

    /// Read the MRTR resume handle for an `input_required` task so a
    /// `tasks/update` can resume it. Returns `Ok(None)` when the task
    /// is not awaiting input. No-op default returns `None`.
    ///
    /// Ownership-gated like every accessor.
    fn task_request_state(
        &self,
        _task_id: &str,
        _session_id: &str,
    ) -> Result<Option<String>, TaskStoreError> {
        Ok(None)
    }

    /// Atomically store the terminal envelope and mark the task terminal.
    ///
    /// Callers pass the exact JSON-RPC response the wrapped request would have
    /// produced (as a [`TerminalEnvelope`]) together with the terminal status
    /// (Completed / Failed / Cancelled). Implementations MUST refuse to rewrite
    /// an already-terminal task.
    fn store_task_terminal(
        &self,
        task_id: &str,
        status: TaskStatus,
        envelope: TerminalEnvelope,
    ) -> Result<(), TaskStoreError>;

    /// Fetch the terminal envelope for a task. Returns `NotCompleted` while
    /// the task is still non-terminal. All terminal states (Completed, Failed,
    /// Cancelled) have a retrievable envelope so `tasks/result` can replay it.
    fn get_task_result(
        &self,
        task_id: &str,
        session_id: &str,
    ) -> Result<TerminalEnvelope, TaskStoreError>;

    /// Cancel a task. Returns updated record. Best-effort — task may already be terminal.
    fn cancel_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError>;

    /// List tasks for a session (with optional cursor pagination).
    fn list_tasks(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Task>, Option<String>), TaskStoreError>;

    /// Garbage-collect expired tasks. Returns number of tasks removed.
    fn gc_expired_tasks(&self) -> usize;
}

// ---------------------------------------------------------------------------
// KvBackedTaskStore — single impl over the orthogonal KvState primitive
// ---------------------------------------------------------------------------

/// Task store backed by any [`mcpg_cluster_api::KeyValueStore`] impl.
///
/// One concrete struct works for every distributed backend (redis, nats,
/// file, …). Replaces the per-backend `RedisTaskStore` / `NatsKvTaskStore`
/// impls that lived in `mcpg-plugin-backend-{redis,nats}` before the
/// substrate was unified behind the cluster API.
///
/// The trait surface stays sync (matches the existing call sites);
/// the impl bridges via `tokio::task::block_in_place` +
/// `Handle::current().block_on(...)`. Making the `TaskStore` trait
/// fully async is a future migration.
///
/// Key scheme: `task:{task_id}` → JSON-encoded [`TaskRecord`].
/// Per-key TTL is the originally-supplied `task.ttl`; backends auto-expire
/// stale entries so [`gc_expired_tasks`] is a no-op for KV-backed stores.
pub struct KvBackedTaskStore {
    state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    policy: TaskRetentionPolicy,
}

impl std::fmt::Debug for KvBackedTaskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedTaskStore")
            .field("policy", &self.policy)
            .finish()
    }
}

impl KvBackedTaskStore {
    pub fn new(
        state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        policy: TaskRetentionPolicy,
    ) -> Self {
        Self { state, policy }
    }

    /// Convenience: in-process `MemoryKv` backing.
    pub fn new_in_memory(policy: TaskRetentionPolicy) -> Self {
        Self::new(
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()),
            policy,
        )
    }

    /// Convenience: in-process backing with a default
    /// `TaskRetentionPolicy` — convenient for tests that don't
    /// exercise retention behaviour.
    pub fn new_in_memory_default() -> Self {
        Self::new_in_memory(TaskRetentionPolicy::default())
    }

    fn task_key(task_id: &str) -> String {
        format!("task:{task_id}")
    }

    fn task_prefix() -> &'static str {
        "task:"
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

    /// Recompute remaining TTL from the record's original creation time and
    /// task.ttl, so updates don't reset the wall-clock expiry.
    fn remaining_ttl(&self, record: &TaskRecord) -> std::time::Duration {
        let original_ttl_ms = record.task.ttl.unwrap_or(self.policy.default_ttl_ms);
        let elapsed_ms = (Utc::now() - record.created_at_utc)
            .num_milliseconds()
            .max(0) as u64;
        let remaining_ms = original_ttl_ms.saturating_sub(elapsed_ms).max(1);
        std::time::Duration::from_millis(remaining_ms)
    }
}

impl TaskStore for KvBackedTaskStore {
    fn retention_policy(&self) -> TaskRetentionPolicy {
        self.policy
    }

    fn create_task(
        &self,
        session_id: &str,
        original_request_id: Value,
        tool_name: &str,
        ttl_ms: Option<u64>,
    ) -> Result<TaskRecord, TaskStoreError> {
        Self::block(async {
            if self.policy.max_tasks_per_session > 0 {
                let entries = self
                    .state
                    .list_prefix(Self::task_prefix(), 4096)
                    .await
                    .map_err(|e| TaskStoreError::Internal(format!("kv list_prefix: {e}")))?;
                let count = entries
                    .iter()
                    .filter(|(_, v)| {
                        serde_json::from_slice::<TaskRecord>(&v.bytes)
                            .map(|r| r.session_id == session_id)
                            .unwrap_or(false)
                    })
                    .count();
                if count >= self.policy.max_tasks_per_session {
                    return Err(TaskStoreError::QuotaExceeded {
                        limit: self.policy.max_tasks_per_session,
                    });
                }
            }
            let now = Utc::now();
            let task_id = Uuid::new_v4().to_string();
            let ttl = ttl_ms.unwrap_or(self.policy.default_ttl_ms);
            let record = TaskRecord {
                task: Task {
                    task_id: task_id.clone(),
                    status: TaskStatus::Working,
                    status_message: None,
                    created_at: now.to_rfc3339(),
                    last_updated_at: now.to_rfc3339(),
                    ttl: Some(ttl),
                    poll_interval: Some(DEFAULT_POLL_INTERVAL_MS),
                },
                session_id: session_id.to_owned(),
                original_request_id,
                tool_name: tool_name.to_owned(),
                created_at_utc: now,
                terminal_envelope: None,
                request_state: None,
                input_requests: None,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(
                    &Self::task_key(&task_id),
                    bytes::Bytes::from(bytes),
                    Some(std::time::Duration::from_millis(ttl)),
                )
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(record)
        })
    }

    fn get_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError> {
        let key = Self::task_key(task_id);
        let value = Self::block(async { self.state.get(&key).await })
            .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
        let v = value.ok_or(TaskStoreError::NotFound)?;
        let record: TaskRecord = serde_json::from_slice(&v.bytes)
            .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
        if record.session_id != session_id {
            return Err(TaskStoreError::Forbidden);
        }
        Ok(record)
    }

    fn update_task_status(
        &self,
        task_id: &str,
        session_id: &str,
        status: TaskStatus,
        status_message: Option<String>,
    ) -> Result<(), TaskStoreError> {
        if is_terminal_status(status) {
            return Err(TaskStoreError::Internal(
                "use store_task_terminal for terminal state transitions".to_owned(),
            ));
        }
        let key = Self::task_key(task_id);
        Self::block(async {
            let value = self
                .state
                .get(&key)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
            let v = value.ok_or(TaskStoreError::NotFound)?;
            let mut record: TaskRecord = serde_json::from_slice(&v.bytes)
                .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
            // Ownership check BEFORE mutating: a different session
            // must not be able to patch this task.
            if record.session_id != session_id {
                return Err(TaskStoreError::Forbidden);
            }
            if is_terminal_status(record.task.status) {
                return Err(TaskStoreError::AlreadyTerminal);
            }
            record.task.status = status;
            record.task.status_message = status_message;
            record.task.last_updated_at = Utc::now().to_rfc3339();
            let ttl = self.remaining_ttl(&record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(ttl))
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(())
        })
    }

    fn set_task_poll_interval(
        &self,
        task_id: &str,
        session_id: &str,
        poll_interval_ms: Option<u64>,
    ) -> Result<(), TaskStoreError> {
        let key = Self::task_key(task_id);
        Self::block(async {
            let value = self
                .state
                .get(&key)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
            let v = value.ok_or(TaskStoreError::NotFound)?;
            let mut record: TaskRecord = serde_json::from_slice(&v.bytes)
                .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
            // Ownership check BEFORE mutating.
            if record.session_id != session_id {
                return Err(TaskStoreError::Forbidden);
            }
            if is_terminal_status(record.task.status) {
                return Err(TaskStoreError::AlreadyTerminal);
            }
            record.task.poll_interval = poll_interval_ms;
            record.task.last_updated_at = Utc::now().to_rfc3339();
            let ttl = self.remaining_ttl(&record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(ttl))
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(())
        })
    }

    fn set_task_awaiting_input(
        &self,
        task_id: &str,
        session_id: &str,
        request_state: String,
        input_requests: Value,
    ) -> Result<(), TaskStoreError> {
        let key = Self::task_key(task_id);
        Self::block(async {
            let value = self
                .state
                .get(&key)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
            let v = value.ok_or(TaskStoreError::NotFound)?;
            let mut record: TaskRecord = serde_json::from_slice(&v.bytes)
                .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
            // Ownership check BEFORE mutating.
            if record.session_id != session_id {
                return Err(TaskStoreError::Forbidden);
            }
            if is_terminal_status(record.task.status) {
                return Err(TaskStoreError::AlreadyTerminal);
            }
            record.task.status = TaskStatus::InputRequired;
            record.task.last_updated_at = Utc::now().to_rfc3339();
            record.request_state = Some(request_state);
            record.input_requests = Some(input_requests);
            let ttl = self.remaining_ttl(&record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(ttl))
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(())
        })
    }

    fn task_request_state(
        &self,
        task_id: &str,
        session_id: &str,
    ) -> Result<Option<String>, TaskStoreError> {
        let record = self.get_task(task_id, session_id)?;
        Ok(record.request_state)
    }

    fn store_task_terminal(
        &self,
        task_id: &str,
        status: TaskStatus,
        envelope: TerminalEnvelope,
    ) -> Result<(), TaskStoreError> {
        if !is_terminal_status(status) {
            return Err(TaskStoreError::Internal(
                "store_task_terminal requires a terminal status".to_owned(),
            ));
        }
        let key = Self::task_key(task_id);
        Self::block(async {
            let value = self
                .state
                .get(&key)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
            let v = value.ok_or(TaskStoreError::NotFound)?;
            let mut record: TaskRecord = serde_json::from_slice(&v.bytes)
                .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
            if is_terminal_status(record.task.status) {
                return Err(TaskStoreError::AlreadyTerminal);
            }
            if let TerminalEnvelope::Error { ref error } = envelope {
                record.task.status_message = Some(error.message.clone());
            }
            record.task.status = status;
            record.task.last_updated_at = Utc::now().to_rfc3339();
            record.terminal_envelope = Some(envelope);
            let ttl = self.remaining_ttl(&record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(ttl))
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(())
        })
    }

    fn get_task_result(
        &self,
        task_id: &str,
        session_id: &str,
    ) -> Result<TerminalEnvelope, TaskStoreError> {
        let record = self.get_task(task_id, session_id)?;
        record.terminal_envelope.ok_or(TaskStoreError::NotCompleted)
    }

    fn cancel_task(&self, task_id: &str, session_id: &str) -> Result<TaskRecord, TaskStoreError> {
        let key = Self::task_key(task_id);
        Self::block(async {
            let value = self
                .state
                .get(&key)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv get: {e}")))?;
            let v = value.ok_or(TaskStoreError::NotFound)?;
            let mut record: TaskRecord = serde_json::from_slice(&v.bytes)
                .map_err(|e| TaskStoreError::Internal(format!("decode TaskRecord: {e}")))?;
            if record.session_id != session_id {
                return Err(TaskStoreError::Forbidden);
            }
            if is_terminal_status(record.task.status) {
                return Err(TaskStoreError::AlreadyTerminal);
            }
            record.task.status = TaskStatus::Cancelled;
            record.task.status_message = Some("Cancelled by client".to_owned());
            record.task.last_updated_at = Utc::now().to_rfc3339();
            record.terminal_envelope = Some(TerminalEnvelope::cancelled(
                record.task.status_message.clone(),
            ));
            let ttl = self.remaining_ttl(&record);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| TaskStoreError::Internal(format!("encode TaskRecord: {e}")))?;
            self.state
                .put(&key, bytes::Bytes::from(bytes), Some(ttl))
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv put: {e}")))?;
            Ok(record)
        })
    }

    fn list_tasks(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Task>, Option<String>), TaskStoreError> {
        Self::block(async {
            let entries = self
                .state
                .list_prefix(Self::task_prefix(), 4096)
                .await
                .map_err(|e| TaskStoreError::Internal(format!("kv list_prefix: {e}")))?;
            let mut session_tasks: Vec<TaskRecord> = entries
                .into_iter()
                .filter_map(|(_, v)| serde_json::from_slice::<TaskRecord>(&v.bytes).ok())
                .filter(|r| r.session_id == session_id)
                .collect();
            session_tasks.sort_by_key(|t| std::cmp::Reverse(t.created_at_utc));
            let start_index = if let Some(cursor_id) = cursor {
                session_tasks
                    .iter()
                    .position(|r| r.task.task_id == cursor_id)
                    .map(|i| i + 1)
                    .unwrap_or(0)
            } else {
                0
            };
            let page: Vec<Task> = session_tasks
                .iter()
                .skip(start_index)
                .take(limit)
                .map(|r| r.task.clone())
                .collect();
            let next_cursor = if start_index + limit < session_tasks.len() {
                page.last().map(|t| t.task_id.clone())
            } else {
                None
            };
            Ok((page, next_cursor))
        })
    }

    fn gc_expired_tasks(&self) -> usize {
        // KV backends auto-expire entries via the TTL passed to `put`; the
        // periodic reaper has nothing to do here. Returning 0 keeps the
        // metric well-defined without scanning every task.
        0
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> KvBackedTaskStore {
        KvBackedTaskStore::new_in_memory_default()
    }

    #[test]
    fn create_task_honors_session_quota() {
        let store = KvBackedTaskStore::new_in_memory(TaskRetentionPolicy {
            default_ttl_ms: 60_000,
            max_tasks_per_session: 2,
            result_wait_ms: 30_000,
        });
        store
            .create_task("sess-1", serde_json::json!(1), "tool", None)
            .expect("first create");
        store
            .create_task("sess-1", serde_json::json!(2), "tool", None)
            .expect("second create");
        let err = store
            .create_task("sess-1", serde_json::json!(3), "tool", None)
            .expect_err("quota should reject the third");
        assert!(matches!(err, TaskStoreError::QuotaExceeded { limit: 2 }));
        // A different session still has room under its own per-session quota.
        store
            .create_task("sess-2", serde_json::json!(9), "tool", None)
            .expect("different session unaffected");
    }

    #[test]
    fn default_ttl_comes_from_policy() {
        let store = KvBackedTaskStore::new_in_memory(TaskRetentionPolicy {
            default_ttl_ms: 12_345,
            max_tasks_per_session: 0,
            result_wait_ms: 30_000,
        });
        let record = store
            .create_task("sess-1", serde_json::json!(1), "tool", None)
            .expect("create");
        assert_eq!(record.task.ttl, Some(12_345));
    }

    #[test]
    fn create_and_get_task() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        assert_eq!(record.task.status, TaskStatus::Working);
        assert_eq!(record.session_id, "sess-1");

        let fetched = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert_eq!(fetched.task.task_id, record.task.task_id);
    }

    #[test]
    fn get_task_forbidden_for_other_session() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let err = store
            .get_task(&record.task.task_id, "sess-other")
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
    }

    #[test]
    fn update_status_advances_working_task() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        store
            .update_task_status(
                &record.task.task_id,
                "sess-1",
                TaskStatus::InputRequired,
                Some("awaiting client".into()),
            )
            .unwrap();
        let updated = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert_eq!(updated.task.status, TaskStatus::InputRequired);
    }

    #[test]
    fn update_status_rejects_terminal_transitions() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        // Callers must use store_task_terminal for Completed/Failed/Cancelled.
        let err = store
            .update_task_status(&record.task.task_id, "sess-1", TaskStatus::Completed, None)
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Internal(_)));
    }

    /// Regression: updateTask must not let a different session patch
    /// another principal's task status, and must NOT mutate before the
    /// ownership check (the old code committed the KV write first).
    #[test]
    fn update_status_forbidden_for_other_session() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let err = store
            .update_task_status(
                &record.task.task_id,
                "sess-attacker",
                TaskStatus::InputRequired,
                Some("tamper".into()),
            )
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
        // The owner's task is untouched (no partial mutation committed).
        let owned = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert_eq!(owned.task.status, record.task.status);
        assert_ne!(owned.task.status, TaskStatus::InputRequired);
    }

    #[test]
    fn store_and_get_terminal_envelope_success() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let envelope = TerminalEnvelope::success(
            serde_json::json!({"content": [{"type": "text", "text": "hello"}]}),
        );
        store
            .store_task_terminal(&record.task.task_id, TaskStatus::Completed, envelope)
            .unwrap();

        let got = store
            .get_task_result(&record.task.task_id, "sess-1")
            .unwrap();
        match got {
            TerminalEnvelope::Success { result } => {
                assert_eq!(result["content"][0]["text"], "hello");
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    fn store_task_terminal_rejects_rewrite() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        store
            .store_task_terminal(
                &record.task.task_id,
                TaskStatus::Completed,
                TerminalEnvelope::success(serde_json::json!({"ok": true})),
            )
            .unwrap();
        let err = store
            .store_task_terminal(
                &record.task.task_id,
                TaskStatus::Failed,
                TerminalEnvelope::error(JsonRpcErrorBody {
                    code: -32000,
                    message: "should be rejected".into(),
                    data: None,
                }),
            )
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::AlreadyTerminal));
    }

    #[test]
    fn get_result_forbidden_for_other_session() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        store
            .store_task_terminal(
                &record.task.task_id,
                TaskStatus::Completed,
                TerminalEnvelope::success(serde_json::json!({})),
            )
            .unwrap();
        let err = store
            .get_task_result(&record.task.task_id, "sess-other")
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
    }

    #[test]
    fn get_result_not_completed() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let err = store
            .get_task_result(&record.task.task_id, "sess-1")
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::NotCompleted));
    }

    #[test]
    fn set_task_poll_interval_persists_for_subsequent_get() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let initial = record.task.poll_interval;

        // Patch to a fresh value and verify it persists.
        store
            .set_task_poll_interval(&record.task.task_id, "sess-1", Some(2_500))
            .unwrap();
        let after = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert_eq!(after.task.poll_interval, Some(2_500));
        assert_ne!(
            after.task.poll_interval, initial,
            "the patch must actually change the stored value"
        );

        // Clearing back to None also persists.
        store
            .set_task_poll_interval(&record.task.task_id, "sess-1", None)
            .unwrap();
        let cleared = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert!(cleared.task.poll_interval.is_none());
    }

    #[test]
    fn set_task_poll_interval_refuses_terminal_task() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        store
            .store_task_terminal(
                &record.task.task_id,
                TaskStatus::Completed,
                TerminalEnvelope::Success {
                    result: serde_json::json!({}),
                },
            )
            .unwrap();
        let err = store
            .set_task_poll_interval(&record.task.task_id, "sess-1", Some(1_000))
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::AlreadyTerminal));
    }

    /// Regression: setPollInterval is ownership-gated too.
    #[test]
    fn set_task_poll_interval_forbidden_for_other_session() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let err = store
            .set_task_poll_interval(&record.task.task_id, "sess-attacker", Some(9_999))
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
        let owned = store.get_task(&record.task.task_id, "sess-1").unwrap();
        assert_ne!(owned.task.poll_interval, Some(9_999));
    }

    #[test]
    fn cancel_task_stores_cancelled_envelope() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let cancelled = store.cancel_task(&record.task.task_id, "sess-1").unwrap();
        assert_eq!(cancelled.task.status, TaskStatus::Cancelled);
        let got = store
            .get_task_result(&record.task.task_id, "sess-1")
            .unwrap();
        match got {
            TerminalEnvelope::Error { error } => assert_eq!(error.code, -32800),
            other => panic!("expected cancellation error envelope, got {other:?}"),
        }
    }

    #[test]
    fn cancel_task_forbidden() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        let err = store
            .cancel_task(&record.task.task_id, "sess-other")
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
    }

    #[test]
    fn cancel_already_terminal_is_rejected() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "test.tool", None)
            .unwrap();
        store
            .store_task_terminal(
                &record.task.task_id,
                TaskStatus::Completed,
                TerminalEnvelope::success(serde_json::json!({})),
            )
            .unwrap();
        let err = store
            .cancel_task(&record.task.task_id, "sess-1")
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::AlreadyTerminal));
    }

    #[test]
    fn list_tasks_filters_by_session() {
        let store = make_store();
        store
            .create_task("sess-1", serde_json::json!(1), "tool-a", None)
            .unwrap();
        let _ = store.create_task("sess-1", serde_json::json!(2), "tool-b", None);
        let _ = store.create_task("sess-2", serde_json::json!(3), "tool-c", None);

        let (tasks, _) = store.list_tasks("sess-1", None, 100).unwrap();
        assert_eq!(tasks.len(), 2);
        let (tasks2, _) = store.list_tasks("sess-2", None, 100).unwrap();
        assert_eq!(tasks2.len(), 1);
    }

    #[test]
    fn list_tasks_pagination() {
        let store = make_store();
        for i in 0..5 {
            store
                .create_task("sess-1", serde_json::json!(i), "tool", None)
                .expect("create_task");
        }

        let (page1, cursor) = store.list_tasks("sess-1", None, 2).unwrap();
        assert_eq!(page1.len(), 2);
        assert!(cursor.is_some());

        let (page2, cursor2) = store.list_tasks("sess-1", cursor.as_deref(), 2).unwrap();
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_some());

        let (page3, cursor3) = store.list_tasks("sess-1", cursor2.as_deref(), 2).unwrap();
        assert_eq!(page3.len(), 1);
        assert!(cursor3.is_none());
    }

    #[test]
    fn kv_auto_expires_via_ttl() {
        // KV-backed stores auto-expire entries through the TTL passed to
        // `put`; the legacy gc-loop is a no-op (returns 0). Verify the
        // record is reachable while TTL is alive and gone after it lapses.
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "tool", Some(50))
            .unwrap();
        assert!(store.get_task(&record.task.task_id, "sess-1").is_ok());

        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(matches!(
            store.get_task(&record.task.task_id, "sess-1"),
            Err(TaskStoreError::NotFound)
        ));
        assert_eq!(store.gc_expired_tasks(), 0);
    }

    #[test]
    fn set_awaiting_input_records_request_state_and_input_requests() {
        let store = make_store();
        let record = store
            .create_task("owner-1", serde_json::json!(1), "tool", None)
            .unwrap();
        // Fresh task carries no resume handle.
        assert!(
            store
                .task_request_state(&record.task.task_id, "owner-1")
                .unwrap()
                .is_none()
        );

        store
            .set_task_awaiting_input(
                &record.task.task_id,
                "owner-1",
                "opaque-resume-blob".to_owned(),
                serde_json::json!({ "elic-1": { "method": "elicitation/create", "params": {} } }),
            )
            .unwrap();

        let updated = store.get_task(&record.task.task_id, "owner-1").unwrap();
        assert_eq!(updated.task.status, TaskStatus::InputRequired);
        assert_eq!(
            store
                .task_request_state(&record.task.task_id, "owner-1")
                .unwrap()
                .as_deref(),
            Some("opaque-resume-blob")
        );
        assert!(updated.input_requests.is_some());
    }

    /// CPN-4 regression: the awaiting-input transition is
    /// ownership-gated — a foreign owner key cannot drive a task into
    /// `input_required` or read its resume handle.
    #[test]
    fn set_awaiting_input_forbidden_for_other_owner() {
        let store = make_store();
        let record = store
            .create_task("owner-1", serde_json::json!(1), "tool", None)
            .unwrap();
        let err = store
            .set_task_awaiting_input(
                &record.task.task_id,
                "attacker",
                "blob".to_owned(),
                serde_json::json!({}),
            )
            .unwrap_err();
        assert!(matches!(err, TaskStoreError::Forbidden));
        let err2 = store
            .task_request_state(&record.task.task_id, "attacker")
            .unwrap_err();
        assert!(matches!(err2, TaskStoreError::Forbidden));
    }

    #[test]
    fn store_failed_terminal_envelope() {
        let store = make_store();
        let record = store
            .create_task("sess-1", serde_json::json!(1), "tool", None)
            .unwrap();
        let envelope = TerminalEnvelope::error(JsonRpcErrorBody {
            code: -32000,
            message: "rate limit exceeded".into(),
            data: None,
        });
        store
            .store_task_terminal(&record.task.task_id, TaskStatus::Failed, envelope)
            .unwrap();
        let got = store
            .get_task_result(&record.task.task_id, "sess-1")
            .unwrap();
        match got {
            TerminalEnvelope::Error { error } => {
                assert_eq!(error.code, -32000);
                assert_eq!(error.message, "rate limit exceeded");
            }
            other => panic!("expected Error envelope, got {other:?}"),
        }
    }
}
