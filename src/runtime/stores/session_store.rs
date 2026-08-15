use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    ClientCapabilities, ImplementationInfo, InitializeParams, JSONRPC_VERSION, LoggingLevel,
    LoggingMessageNotification, LoggingMessageParams, ProtocolResponse,
};
use crate::runtime::ResumeCursor;

/// Session lifecycle state machine: sessions start in `AwaitingInitialized` after
/// the `initialize` request, transition to `Operational` after `notifications/initialized`,
/// and are destroyed on DELETE or idle timeout. All capability operations require `Operational`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
    AwaitingInitialized,
    Operational,
}

/// Point-in-time snapshot of a session's state, used for read-only queries
/// without holding a lock on the session store.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub protocol_version: String,
    pub client_info: ImplementationInfo,
    pub client_capabilities: ClientCapabilities,
    pub phase: SessionPhase,
    pub log_level: LoggingLevel,
    pub created_at: DateTime<Utc>,
    /// Trust-qualified principal key of the session creator (`None` =
    /// anonymous). Surfaced so the HTTP layer can enforce session-owner
    /// binding.
    pub owner_principal: Option<String>,
}

/// A single SSE event stored in the replay window. When a client reconnects with
/// `Last-Event-Id`, the store replays all events with IDs after the cursor so
/// the client never misses a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SseEventRecord {
    pub event_id: String,
    pub data: String,
    pub retry_ms: Option<u64>,
}

/// Tuning knobs for the session store: replay window depth, idle timeout,
/// and capacity limits. The multi-backend architecture (in-memory, file, NATS KV,
/// Redis) shares this config; each backend maps limits to its storage model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStoreConfig {
    pub replay_window_limit: usize,
    pub session_idle_timeout_ms: u64,
    /// Maximum number of concurrent sessions. 0 = unlimited.
    pub max_sessions: usize,
    /// Per-tenant session quota. 0 = unlimited. The stricter of this
    /// and `max_sessions` wins.
    pub max_sessions_per_tenant: usize,
}

impl Default for SessionStoreConfig {
    fn default() -> Self {
        Self {
            replay_window_limit: 16,
            session_idle_timeout_ms: 900_000,
            max_sessions: 10_000,
            max_sessions_per_tenant: 0,
        }
    }
}

/// Errors from session lookup operations, mapped to JSON-RPC error responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAccessError {
    MissingSessionId,
    UnknownSession,
    NotInitialized,
}

/// Errors from SSE stream operations, mapped to HTTP status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAccessError {
    MissingSessionId,
    UnknownSession,
    NotInitialized,
    InvalidCursor,
    ExpiredCursor,
}

pub trait SessionStore: Send + Sync {
    /// Persist a new session.
    ///
    /// `negotiated_protocol_version` is the version the runtime selected after
    /// inspecting the client's `InitializeParams.protocol_version`. The store
    /// must record this negotiated value, not the raw client-requested string,
    /// so later request handling operates on what was actually agreed.
    fn create_session(
        &self,
        negotiated_protocol_version: &str,
        params: &InitializeParams,
    ) -> SessionSnapshot;
    /// Create a session under a caller-supplied id, returning the existing
    /// snapshot unchanged if one already lives at `session_id` (idempotent).
    ///
    /// Used by modern (DRAFT-2026-v1) stateless mode: every replica
    /// derives the same deterministic id for a principal, so the session
    /// row — persisted to cluster KV — is shared. The default impl ignores
    /// the id and mints a random one (in-process stores have no cross-
    /// replica notion); cluster-KV-backed stores override.
    fn create_session_with_id(
        &self,
        session_id: &str,
        negotiated_protocol_version: &str,
        params: &InitializeParams,
    ) -> SessionSnapshot {
        let _ = session_id;
        self.create_session(negotiated_protocol_version, params)
    }
    /// Record the principal that owns `session_id`. Used by the HTTP
    /// layer to bind session-scoped operations to their creator when
    /// `sessions.bind_session_owner` is enabled. Default no-op for
    /// in-process / test stores that don't surface owner binding.
    fn bind_session_owner(&self, session_id: &str, owner_principal: Option<&str>) {
        let _ = (session_id, owner_principal);
    }
    fn session_protocol_version(&self, session_id: &str) -> Option<String>;
    fn load_session(
        &self,
        session_id: Option<&str>,
        require_operational: bool,
    ) -> Result<SessionSnapshot, SessionAccessError>;
    fn transition_session_to_operational(&self, session_id: &str)
    -> Result<(), SessionAccessError>;
    fn set_session_log_level(
        &self,
        session_id: Option<&str>,
        level: LoggingLevel,
    ) -> Result<(), SessionAccessError>;
    fn terminate_session(&self, session_id: &str) -> bool;
    /// Register a sink notified with the session id whenever the store drops
    /// a session due to idle EXPIRY (not explicit `terminate_session`, which
    /// the runtime already cascades). Lets the runtime run its per-session
    /// cleanup cascade for sessions the client never terminates. Default no-op
    /// (in-process test stores need no cascade).
    fn set_eviction_notifier(&self, notifier: tokio::sync::mpsc::UnboundedSender<String>) {
        let _ = notifier;
    }
    /// Side-effect-free check: is a session with this id currently held in the
    /// store's live (in-memory) set? Unlike `load_session` this must NOT
    /// re-hydrate from the backing KV, so the idle-eviction cascade can tell a
    /// truly-gone session from one a client re-created under the same id.
    /// Default `false` (no live set) — cascade proceeds.
    fn contains_active_session(&self, session_id: &str) -> bool {
        let _ = session_id;
        false
    }
    fn open_sse_stream(
        &self,
        session_id: Option<&str>,
        resume_cursor: Option<&ResumeCursor>,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError>;
    fn stream_protocol_response(
        &self,
        session_id: &str,
        protocol_response: &ProtocolResponse,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.stream_protocol_response_with_pending(session_id, protocol_response, &[])
    }
    /// Like [`Self::stream_protocol_response`] but interleaves
    /// `pending_notifications` (each a serialised JSON-RPC notification
    /// envelope) between the priming/logging events and the terminal
    /// response. Used by the legacy POST→SSE path to inject `log` /
    /// `progress` notifications produced inside the same pipeline
    /// invocation onto the response stream BEFORE the result so the
    /// client SDK matches them to the in-flight request.
    fn stream_protocol_response_with_pending(
        &self,
        session_id: &str,
        protocol_response: &ProtocolResponse,
        pending_notifications: &[String],
    ) -> Result<Vec<SseEventRecord>, StreamAccessError>;
    fn stream_raw_message(
        &self,
        session_id: &str,
        message_json: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError>;

    /// Like [`Self::stream_raw_message`] but tags the emitted SSE event id
    /// with the originating coordinator-KV `delivery_id` (as an opaque
    /// `@{delivery_id}` suffix). A later reconnect that echoes this id as
    /// `Last-Event-Id` lets the gateway delete the exact backlog row the
    /// client already received, so a live-delivered server-push is not
    /// replayed from the backlog. Defaults to the untagged
    /// path so non-delivery / test impls need no change.
    fn stream_delivery_message(
        &self,
        session_id: &str,
        message_json: &str,
        _delivery_id: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.stream_raw_message(session_id, message_json)
    }

    /// Stream a delivery, choosing the tagged or untagged path by whether it
    /// carries a backlog id. Sole owner of that choice, so the runtime and the
    /// transport's SSE forwarder cannot disagree about when a replay tag is
    /// emitted.
    fn stream_message(
        &self,
        session_id: &str,
        message_json: &str,
        delivery_id: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        if delivery_id.is_empty() {
            self.stream_raw_message(session_id, message_json)
        } else {
            self.stream_delivery_message(session_id, message_json, delivery_id)
        }
    }

    /// List active sessions. Returns summary snapshots.
    fn list_sessions(&self) -> Vec<SessionSnapshot> {
        vec![]
    }

    /// Count active sessions without allocating.
    fn active_session_count(&self) -> usize {
        self.list_sessions().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    session_id: String,
    protocol_version: String,
    client_info: ImplementationInfo,
    client_capabilities: ClientCapabilities,
    phase: SessionPhase,
    log_level: LoggingLevel,
    next_stream_ordinal: u64,
    streams: HashMap<String, StoredStream>,
    /// The stream that receives server-initiated messages. Updated on
    /// every `open_sse_stream`; ensures deterministic delivery routing.
    #[serde(default)]
    active_stream_id: Option<String>,
    /// Trust-qualified principal key of the session creator (trust tier +
    /// provider + issuer + subject; `None` for an anonymous creator).
    /// Used by the HTTP layer to bind session-scoped operations
    /// (GET/DELETE/subscribe/continuation) to their owner when
    /// `sessions.bind_session_owner` is enabled.
    #[serde(default)]
    owner_principal: Option<String>,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

impl StoredSession {
    fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            session_id: self.session_id.clone(),
            protocol_version: self.protocol_version.clone(),
            client_info: self.client_info.clone(),
            client_capabilities: self.client_capabilities.clone(),
            phase: self.phase,
            log_level: self.log_level,
            created_at: self.created_at,
            owner_principal: self.owner_principal.clone(),
        }
    }

    fn touch(&mut self) {
        self.last_seen_at = Utc::now();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredStream {
    replay_window: VecDeque<SseEventRecord>,
    next_event_ordinal: u64,
    /// Token bucket for `notifications/message` rate limiting. Not
    /// persisted; `None` until the first log attempt fills it lazily.
    #[serde(skip)]
    log_bucket: Option<LogTokenBucket>,
}

/// Per-stream token bucket for logging-notification rate limiting.
#[derive(Debug, Clone)]
struct LogTokenBucket {
    tokens: f64,
    last_refill: std::time::Instant,
}

/// Default cadence: 50 log messages per second per stream, burst 100.
/// High enough that ordinary logging is unaffected; low enough that a
/// run-away error loop cannot saturate the delivery bus.
const LOG_RATE_PER_SEC: f64 = 50.0;
const LOG_RATE_BURST: f64 = 100.0;

impl LogTokenBucket {
    fn take(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * LOG_RATE_PER_SEC).min(LOG_RATE_BURST);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

const SSE_RETRY_MS: u64 = 1500;

/// Check if the session limit is reached. Returns `Some(rejection_snapshot)` if the
/// limit is exceeded, `None` if the session can be created.
fn check_session_limit(
    sessions: &dashmap::DashMap<String, StoredSession>,
    config: &SessionStoreConfig,
    protocol_version: &str,
) -> Option<SessionSnapshot> {
    if config.max_sessions > 0 && sessions.len() >= config.max_sessions {
        tracing::warn!(
            current = sessions.len(),
            max = config.max_sessions,
            "session limit reached, rejecting new session"
        );
        return Some(SessionSnapshot {
            session_id: String::new(),
            protocol_version: protocol_version.to_owned(),
            client_info: crate::protocol::ImplementationInfo {
                name: String::new(),
                title: None,
                version: String::new(),
                description: None,
                website_url: None,
                icons: None,
            },
            client_capabilities: Default::default(),
            phase: SessionPhase::AwaitingInitialized,
            log_level: LoggingLevel::Info,
            created_at: chrono::Utc::now(),
            owner_principal: None,
        });
    }
    None
}

fn append_event(
    stream: &mut StoredStream,
    stream_id: &str,
    data: String,
    retry_ms: Option<u64>,
    replay_window_limit: usize,
) -> SseEventRecord {
    append_event_with_delivery(stream, stream_id, data, retry_ms, replay_window_limit, None)
}

/// Separator between the canonical `{stream_id}:{ordinal}` event id and the
/// optional coordinator-KV delivery id it carried. The delivery id
/// (`{seq}-{uuid}`) never contains this byte, and the stream-id/ordinal
/// never do either, so the split is unambiguous. The suffix is opaque to
/// clients (which echo the whole `Last-Event-Id` back); the gateway parses
/// it on reconnect to prune the acknowledged backlog row so an
/// already-delivered server-push is not replayed.
const DELIVERY_ID_SEP: char = '@';

/// Like [`append_event`] but, when `delivery_id` is `Some`, appends an
/// opaque `@{delivery_id}` suffix to the event id. The suffix lets a later
/// reconnect carrying this id as `Last-Event-Id` identify (and delete) the
/// exact coordinator-KV backlog row the client already received, so a
/// live-delivered terminal result is not replayed from the backlog.
fn append_event_with_delivery(
    stream: &mut StoredStream,
    stream_id: &str,
    data: String,
    retry_ms: Option<u64>,
    replay_window_limit: usize,
    delivery_id: Option<&str>,
) -> SseEventRecord {
    let ordinal = stream.next_event_ordinal;
    let event_id = match delivery_id {
        Some(did) => format!("{stream_id}:{ordinal}{DELIVERY_ID_SEP}{did}"),
        None => format!("{stream_id}:{ordinal}"),
    };
    stream.next_event_ordinal += 1;
    let record = SseEventRecord {
        event_id,
        data,
        retry_ms,
    };
    stream.replay_window.push_back(record.clone());
    while stream.replay_window.len() > replay_window_limit {
        stream.replay_window.pop_front();
    }
    record
}

/// Strip the optional `@{delivery_id}` suffix from an event id, returning
/// the canonical `{stream_id}:{ordinal}` core. Event ids never carry the
/// separator unless a server-push delivery added one, so this is a no-op
/// for ordinary stream events.
fn event_id_core(event_id: &str) -> &str {
    match event_id.split_once(DELIVERY_ID_SEP) {
        Some((core, _delivery_id)) => core,
        None => event_id,
    }
}

/// Extract the coordinator-KV delivery id a client acknowledged by echoing
/// it inside `Last-Event-Id`. `None` when the cursor is an ordinary stream
/// event (no server-push delivery suffix).
pub(crate) fn delivery_id_from_event_id(event_id: &str) -> Option<&str> {
    event_id
        .split_once(DELIVERY_ID_SEP)
        .map(|(_core, delivery_id)| delivery_id)
        .filter(|d| !d.is_empty())
}

fn logging_notification_event(
    stream: &mut StoredStream,
    stream_id: &str,
    session_log_level: LoggingLevel,
    event_level: LoggingLevel,
    logger: &str,
    data: serde_json::Value,
    replay_window_limit: usize,
) -> Option<SseEventRecord> {
    if event_level < session_log_level {
        return None;
    }

    // Rate-limit log notifications so a runaway loop cannot amplify
    // into SSE backpressure. Critical+ bypasses the limiter.
    let bypass = matches!(
        event_level,
        LoggingLevel::Critical | LoggingLevel::Alert | LoggingLevel::Emergency
    );
    if !bypass {
        let bucket = stream.log_bucket.get_or_insert(LogTokenBucket {
            tokens: LOG_RATE_BURST,
            last_refill: std::time::Instant::now(),
        });
        if !bucket.take() {
            metrics::counter!(
                "mcpg_logging_notification_rate_limited_total",
                "logger" => logger.to_owned(),
            )
            .increment(1);
            return None;
        }
    }

    // Security: scrub credential-shaped values before replay buffer.
    let data = crate::runtime::redact::redact_credentials(&data);

    let notification = LoggingMessageNotification {
        jsonrpc: JSONRPC_VERSION,
        method: "notifications/message",
        params: LoggingMessageParams {
            level: event_level,
            logger: Some(logger.to_owned()),
            data,
        },
    };

    Some(append_event(
        stream,
        stream_id,
        serde_json::to_string(&notification).expect("logging notification serialized"),
        None,
        replay_window_limit,
    ))
}

fn parse_event_id(event_id: &str) -> Option<(&str, u64)> {
    // Strip any opaque `@{delivery_id}` suffix first so the canonical
    // `{stream_id}:{ordinal}` core parses identically whether or not the
    // client echoed a delivery-tagged cursor back.
    let (stream_id, ordinal) = event_id_core(event_id).rsplit_once(':')?;
    let ordinal = ordinal.parse().ok()?;
    Some((stream_id, ordinal))
}

fn event_ordinal(event_id: &str) -> Option<u64> {
    parse_event_id(event_id).map(|(_, ordinal)| ordinal)
}

// ---------------------------------------------------------------------------
// KvBackedSessionStore — single impl over the orthogonal KvState primitive
// ---------------------------------------------------------------------------

/// Session store backed by any [`mcpg_cluster_api::KeyValueStore`] impl.
///
/// Replaces the per-backend `RedisSessionStore` / `NatsKvSessionStore`
/// impls that lived in `mcpg-plugin-backend-{redis,nats}` before the
/// substrate was unified behind the cluster API.
///
/// In-memory `HashMap` is the hot working set; every mutation also
/// serialises the [`StoredSession`] to KV. On boot, all live sessions
/// are hydrated via `list_prefix("session:")` so a replica restart
/// picks up where it left off.
///
/// Sticky sessions (per-replica session affinity) are an external
/// invariant — without them, two replicas writing the same session
/// concurrently race on KV and the last-writer wins. A future
/// `LeaseState`-backed cluster-strict claim could remove that
/// requirement if stickiness can't be enforced.
pub struct KvBackedSessionStore {
    config: SessionStoreConfig,
    state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    /// Sharded so requests on different sessions don't serialise on one lock
    /// (each session's stream ordinals / replay window still serialise via the
    /// per-key shard guard). Expiry is lazy per-entry on access + a throttled
    /// full sweep (`maybe_sweep`), NOT an O(N) scan on every request.
    sessions: dashmap::DashMap<String, StoredSession>,
    /// Epoch-ms of the last full idle sweep; throttles `maybe_sweep`.
    last_pruned: std::sync::atomic::AtomicI64,
    /// Registered once (by the runtime at boot) to receive the id of every
    /// session this store drops due to idle expiry. Explicit
    /// `terminate_session` runs the runtime's full per-session cleanup
    /// cascade; idle eviction otherwise skips it, so those ids are forwarded
    /// here for the runtime to cascade. `None` until registered / in tests.
    eviction_tx: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl std::fmt::Debug for KvBackedSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvBackedSessionStore")
            .field("config", &self.config)
            .finish()
    }
}

impl KvBackedSessionStore {
    /// Sync constructor over an empty in-process `MemoryKv`. Skips
    /// the async hydrate step `new` runs against persistent backings
    /// — there's nothing to hydrate from a freshly-allocated map.
    /// Useful for tests + the `cluster.kind: single_node` boot path
    /// where async hydration would be a wasted round-trip.
    pub fn new_in_memory(config: SessionStoreConfig) -> Self {
        Self {
            config,
            state: std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()),
            sessions: dashmap::DashMap::new(),
            last_pruned: std::sync::atomic::AtomicI64::new(0),
            eviction_tx: std::sync::OnceLock::new(),
        }
    }

    /// Lazy per-entry expiry: atomically evict `session_id` iff it is still
    /// idle-expired (the `remove_if` predicate re-checks under the shard lock,
    /// so a concurrent `touch()` can't be clobbered). O(1); replaces the old
    /// per-request O(N) whole-map scan.
    /// Forward an idle-evicted session id to the runtime cleanup cascade, if a
    /// notifier is registered. Non-blocking; a full/closed channel is ignored
    /// (the runtime falls back to nothing worse than today's behaviour).
    fn notify_evicted(&self, session_id: &str) {
        if let Some(tx) = self.eviction_tx.get() {
            let _ = tx.send(session_id.to_owned());
        }
    }

    fn evict_if_expired(&self, session_id: &str) {
        let timeout = self.config.session_idle_timeout_ms;
        let removed = self.sessions.remove_if(session_id, |_, s| {
            (Utc::now() - s.last_seen_at).num_milliseconds().max(0) as u64 >= timeout
        });
        if removed.is_some() {
            self.notify_evicted(session_id);
        }
    }

    /// Throttled full idle sweep: at most once per timeout window (capped at
    /// 60s), retain only live sessions and delete evicted KV rows. Piggybacks
    /// on request traffic — the common path is a single atomic load + early
    /// return; the actual `retain` (which briefly locks every shard) runs
    /// rarely, so never-reaccessed sessions are still reaped without an O(N)
    /// scan on the hot path.
    fn maybe_sweep(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = Utc::now().timestamp_millis();
        let interval = (self.config.session_idle_timeout_ms as i64).clamp(1, 60_000);
        let last = self.last_pruned.load(Relaxed);
        if now - last < interval {
            return;
        }
        if self
            .last_pruned
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_err()
        {
            return; // another thread is sweeping this window
        }
        let timeout = self.config.session_idle_timeout_ms;
        let mut evicted: Vec<String> = Vec::new();
        self.sessions.retain(|id, s| {
            let live = ((Utc::now() - s.last_seen_at).num_milliseconds().max(0) as u64) < timeout;
            if !live {
                evicted.push(id.clone());
            }
            live
        });
        for id in evicted {
            self.remove_session(&id);
            self.notify_evicted(&id);
        }
    }

    pub async fn new(
        config: SessionStoreConfig,
        state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    ) -> anyhow::Result<Self> {
        let entries = state
            .list_prefix("session:", 4096)
            .await
            .map_err(|e| anyhow::anyhow!("kv list_prefix on hydrate: {e}"))?;
        let now = Utc::now();
        let sessions = dashmap::DashMap::new();
        for (key, value) in entries {
            let session: StoredSession = match serde_json::from_slice(&value.bytes) {
                Ok(s) => s,
                Err(_) => {
                    let _ = state.delete(&key).await;
                    continue;
                }
            };
            let age_ms = (now - session.last_seen_at).num_milliseconds().max(0) as u64;
            if age_ms >= config.session_idle_timeout_ms {
                let _ = state.delete(&key).await;
                continue;
            }
            sessions.insert(session.session_id.clone(), session);
        }
        Ok(Self {
            config,
            state,
            sessions,
            last_pruned: std::sync::atomic::AtomicI64::new(0),
            eviction_tx: std::sync::OnceLock::new(),
        })
    }

    /// Convenience constructor over a `FileKv` rooted at `data_dir`.
    /// Hydrates surviving sessions from disk on boot.
    pub async fn new_with_file(
        config: SessionStoreConfig,
        data_dir: impl AsRef<std::path::Path>,
    ) -> anyhow::Result<Self> {
        let kv = crate::builtins::cluster_primitives::FileKv::new(data_dir.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("FileKv init: {e}"))?;
        Self::new(
            config,
            kv as std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        )
        .await
    }

    fn session_key(session_id: &str) -> String {
        format!("session:{session_id}")
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
            // current_thread runtime (e.g. default `#[tokio::test]`) or no
            // tokio context: fall back to a thread-local executor. Safe for
            // primitives that don't require the tokio reactor (e.g. MemoryKv);
            // real I/O backends (Redis, NATS) only run under multi-thread
            // runtimes in production.
            _ => futures::executor::block_on(fut),
        }
    }

    fn persist_session(&self, session: &StoredSession) {
        let key = Self::session_key(&session.session_id);
        let bytes = match serde_json::to_vec(session) {
            Ok(b) => b,
            Err(_) => return,
        };
        let payload = bytes::Bytes::from(bytes);
        let _ = Self::block(async { self.state.put(&key, payload, None).await });
    }

    /// Persist a freshly-created session row with create-once semantics:
    /// an atomic `put_if_absent` rather than a last-writer-wins `put`. The
    /// session id is a fresh random UUID, so the key is effectively always
    /// absent and this wins; the create-once guard simply means two replicas
    /// that ever derive the same id (or a re-create after a read-back) cannot
    /// clobber a live row. Mirrors the modern deterministic-id create path,
    /// which already converges idempotently. Returns whether the row was
    /// written by this call.
    fn persist_session_create_once(&self, session: &StoredSession) -> bool {
        let key = Self::session_key(&session.session_id);
        let bytes = match serde_json::to_vec(session) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let payload = bytes::Bytes::from(bytes);
        Self::block(async { self.state.put_if_absent(&key, payload, None).await }).unwrap_or(false)
    }

    fn remove_session(&self, session_id: &str) {
        let key = Self::session_key(session_id);
        let _ = Self::block(async { self.state.delete(&key).await });
    }

    /// Cross-replica / post-failover session continuity: if `session_id`
    /// is absent from the in-memory working set, read it back from the
    /// shared KV and insert it, so a session created on another replica
    /// (or before a restart) resolves here instead of 404'ing.
    ///
    /// No-op — and NO KV round-trip — when the session is already local
    /// (the sticky-session / same-replica happy path). The `sessions`
    /// lock is held only for the membership check and the final insert,
    /// never across the (blocking) KV read. Mirrors `new()`'s
    /// boot-hydrate idle-timeout check so a read-back behaves identically
    /// to a restart hydrate.
    fn ensure_hydrated(&self, session_id: &str) {
        if self.sessions.contains_key(session_id) {
            return;
        }
        let key = Self::session_key(session_id);
        let value = match Self::block(async { self.state.get(&key).await }) {
            Ok(Some(v)) => v,
            // KV miss or backend error → leave absent; the caller's
            // existing `ok_or(UnknownSession)` handles it.
            _ => return,
        };
        let session: StoredSession = match serde_json::from_slice(&value.bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let age_ms = (Utc::now() - session.last_seen_at)
            .num_milliseconds()
            .max(0) as u64;
        if age_ms >= self.config.session_idle_timeout_ms {
            let _ = Self::block(async { self.state.delete(&key).await });
            return;
        }
        // `or_insert` (not overwrite): if a concurrent request hydrated
        // or created the same id while we read KV, keep the live copy.
        self.sessions
            .entry(session.session_id.clone())
            .or_insert(session);
    }

    /// Shared body for `stream_raw_message` / `stream_delivery_message`:
    /// append `message_json` as a new event on the session's active stream,
    /// optionally tagging the event id with `delivery_id`.
    fn stream_message_inner(
        &self,
        session_id: &str,
        message_json: &str,
        delivery_id: Option<&str>,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(StreamAccessError::UnknownSession)?;
        if session.phase != SessionPhase::Operational {
            return Err(StreamAccessError::NotInitialized);
        }
        session.touch();
        let stream_id = session
            .active_stream_id
            .clone()
            .ok_or(StreamAccessError::NotInitialized)?;
        let stream = session
            .streams
            .get_mut(&stream_id)
            .ok_or(StreamAccessError::UnknownSession)?;
        let event = append_event_with_delivery(
            stream,
            &stream_id,
            message_json.to_owned(),
            None,
            self.config.replay_window_limit,
            delivery_id,
        );
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
        Ok(vec![event])
    }
}

impl SessionStore for KvBackedSessionStore {
    fn create_session(
        &self,
        negotiated_protocol_version: &str,
        params: &InitializeParams,
    ) -> SessionSnapshot {
        let now = Utc::now();
        let session = StoredSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            protocol_version: negotiated_protocol_version.to_owned(),
            client_info: params.client_info.clone(),
            client_capabilities: params.capabilities.clone(),
            phase: SessionPhase::AwaitingInitialized,
            log_level: LoggingLevel::Info,
            next_stream_ordinal: 0,
            streams: HashMap::new(),
            active_stream_id: None,
            owner_principal: None,
            last_seen_at: now,
            created_at: now,
        };
        let snapshot = session.snapshot();
        self.maybe_sweep();
        if let Some(rejection) =
            check_session_limit(&self.sessions, &self.config, &session.protocol_version)
        {
            return rejection;
        }
        // Create-once: a fresh random-UUID session must not clobber a live
        // row of the same id (mirrors the modern deterministic-id path).
        self.persist_session_create_once(&session);
        self.sessions.insert(session.session_id.clone(), session);
        snapshot
    }

    fn create_session_with_id(
        &self,
        session_id: &str,
        negotiated_protocol_version: &str,
        params: &InitializeParams,
    ) -> SessionSnapshot {
        // Idempotent: if the row already exists (this replica, or another
        // via the KV read-back hydration), return it unchanged so
        // concurrent cross-replica creates of the same deterministic id
        // converge on one session rather than clobbering each other.
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        if let Some(mut existing) = self.sessions.get_mut(session_id) {
            existing.touch();
            let snap = existing.snapshot();
            let stored = existing.clone();
            drop(existing);
            self.persist_session(&stored);
            return snap;
        }
        let now = Utc::now();
        let session = StoredSession {
            session_id: session_id.to_owned(),
            protocol_version: negotiated_protocol_version.to_owned(),
            client_info: params.client_info.clone(),
            client_capabilities: params.capabilities.clone(),
            phase: SessionPhase::AwaitingInitialized,
            log_level: LoggingLevel::Info,
            next_stream_ordinal: 0,
            streams: HashMap::new(),
            active_stream_id: None,
            owner_principal: None,
            last_seen_at: now,
            created_at: now,
        };
        let snapshot = session.snapshot();
        self.maybe_sweep();
        if let Some(rejection) =
            check_session_limit(&self.sessions, &self.config, &session.protocol_version)
        {
            return rejection;
        }
        self.persist_session(&session);
        self.sessions.insert(session.session_id.clone(), session);
        snapshot
    }

    fn bind_session_owner(&self, session_id: &str, owner_principal: Option<&str>) {
        self.ensure_hydrated(session_id);
        let Some(mut session) = self.sessions.get_mut(session_id) else {
            return;
        };
        session.owner_principal = owner_principal.map(str::to_owned);
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
    }

    fn session_protocol_version(&self, session_id: &str) -> Option<String> {
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        let mut session = self.sessions.get_mut(session_id)?;
        session.touch();
        let version = session.protocol_version.clone();
        let snapshot = session.clone();
        drop(session);
        self.persist_session(&snapshot);
        Some(version)
    }

    fn load_session(
        &self,
        session_id: Option<&str>,
        require_operational: bool,
    ) -> Result<SessionSnapshot, SessionAccessError> {
        let session_id = session_id.ok_or(SessionAccessError::MissingSessionId)?;
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        self.maybe_sweep();
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionAccessError::UnknownSession)?;
        session.touch();
        if require_operational && session.phase != SessionPhase::Operational {
            return Err(SessionAccessError::NotInitialized);
        }
        // A read only bumps `last_seen_at` in memory. Persisting it here would
        // run a blocking KV write (`block_in_place`) on EVERY request, which
        // thrashes the tokio worker pool under load. State changes still
        // persist; the read-touch is durably re-established on the next real
        // mutation (worst case: a stale `last_seen_at` on cross-replica
        // failover, which only shortens an idle timeout).
        Ok(session.snapshot())
    }

    fn transition_session_to_operational(
        &self,
        session_id: &str,
    ) -> Result<(), SessionAccessError> {
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        self.maybe_sweep();
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionAccessError::UnknownSession)?;
        session.phase = SessionPhase::Operational;
        session.touch();
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
        Ok(())
    }

    fn set_session_log_level(
        &self,
        session_id: Option<&str>,
        level: LoggingLevel,
    ) -> Result<(), SessionAccessError> {
        let session_id = session_id.ok_or(SessionAccessError::MissingSessionId)?;
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        self.maybe_sweep();
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(SessionAccessError::UnknownSession)?;
        if session.phase != SessionPhase::Operational {
            return Err(SessionAccessError::NotInitialized);
        }
        session.log_level = level;
        session.touch();
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
        Ok(())
    }

    fn terminate_session(&self, session_id: &str) -> bool {
        // Hydrate first so a DELETE/terminate that lands on a replica
        // which never saw the session still removes the shared KV copy —
        // otherwise the session would resurrect via read-back elsewhere.
        self.ensure_hydrated(session_id);
        let removed = self.sessions.remove(session_id).is_some();
        if removed {
            self.remove_session(session_id);
        }
        removed
    }

    fn set_eviction_notifier(&self, notifier: tokio::sync::mpsc::UnboundedSender<String>) {
        let _ = self.eviction_tx.set(notifier);
    }

    fn contains_active_session(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    fn open_sse_stream(
        &self,
        session_id: Option<&str>,
        resume_cursor: Option<&ResumeCursor>,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        let session_id = session_id.ok_or(StreamAccessError::MissingSessionId)?;
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(StreamAccessError::UnknownSession)?;
        if session.phase != SessionPhase::Operational {
            return Err(StreamAccessError::NotInitialized);
        }
        session.touch();

        if let Some(resume_cursor) = resume_cursor {
            let (stream_id, last_ordinal) = parse_event_id(&resume_cursor.last_event_id)
                .ok_or(StreamAccessError::InvalidCursor)?;
            let stream = session
                .streams
                .get(stream_id)
                .ok_or(StreamAccessError::InvalidCursor)?;
            // Compare on the canonical `{stream_id}:{ordinal}` core so a
            // delivery-tagged cursor still matches its stored record
            // regardless of the opaque delivery-id suffix.
            let cursor_core = event_id_core(&resume_cursor.last_event_id);
            let cursor_still_retained = stream
                .replay_window
                .iter()
                .any(|event| event_id_core(&event.event_id) == cursor_core);
            if !cursor_still_retained {
                return Err(StreamAccessError::ExpiredCursor);
            }
            let events = stream
                .replay_window
                .iter()
                .filter(|event| {
                    event_ordinal(&event.event_id).is_some_and(|ordinal| ordinal > last_ordinal)
                })
                .cloned()
                .collect();
            let stored = session.clone();
            drop(session);
            self.persist_session(&stored);
            return Ok(events);
        }

        if let Some(ref prev) = session.active_stream_id {
            tracing::info!(
                session_id = %session.session_id,
                previous_stream = %prev,
                "active SSE stream superseded by a new GET"
            );
            metrics::counter!("mcpg_sse_active_stream_superseded_total").increment(1);
        }
        let stream_id = format!("stream-{}", session.next_stream_ordinal);
        session.next_stream_ordinal += 1;
        session.active_stream_id = Some(stream_id.clone());
        let session_id_owned = session.session_id.clone();
        let log_level = session.log_level;
        let stream = session
            .streams
            .entry(stream_id.clone())
            .or_insert_with(StoredStream::default);
        let prime_event = append_event(
            stream,
            &stream_id,
            String::new(),
            Some(SSE_RETRY_MS),
            self.config.replay_window_limit,
        );
        let logging_event = logging_notification_event(
            stream,
            &stream_id,
            log_level,
            LoggingLevel::Info,
            "mcpg.transport",
            serde_json::json!({
                "message": "SSE stream opened",
                "sessionId": session_id_owned,
            }),
            self.config.replay_window_limit,
        );
        let events = match logging_event {
            Some(logging_event) => vec![prime_event, logging_event],
            None => vec![prime_event],
        };
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
        Ok(events)
    }

    fn stream_protocol_response_with_pending(
        &self,
        session_id: &str,
        protocol_response: &ProtocolResponse,
        pending_notifications: &[String],
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or(StreamAccessError::UnknownSession)?;
        if session.phase != SessionPhase::Operational {
            return Err(StreamAccessError::NotInitialized);
        }
        session.touch();

        if let Some(ref prev) = session.active_stream_id {
            tracing::info!(
                session_id = %session.session_id,
                previous_stream = %prev,
                "active SSE stream superseded by a new GET"
            );
            metrics::counter!("mcpg_sse_active_stream_superseded_total").increment(1);
        }
        let stream_id = format!("stream-{}", session.next_stream_ordinal);
        session.next_stream_ordinal += 1;
        session.active_stream_id = Some(stream_id.clone());
        let session_id_owned = session.session_id.clone();
        let log_level = session.log_level;
        let stream = session
            .streams
            .entry(stream_id.clone())
            .or_insert_with(StoredStream::default);
        let prime_event = append_event(
            stream,
            &stream_id,
            String::new(),
            Some(SSE_RETRY_MS),
            self.config.replay_window_limit,
        );
        let logging_event = logging_notification_event(
            stream,
            &stream_id,
            log_level,
            LoggingLevel::Info,
            "mcpg.transport",
            serde_json::json!({
                "message": "Streaming protocol response",
                "sessionId": session_id_owned,
            }),
            self.config.replay_window_limit,
        );
        // Pending notifications collected by the pipeline executor during
        // this same request (e.g. `log` / `progress` steps). Injected
        // BEFORE the terminal response so the client matches them to the
        // in-flight tools/call.
        let mut pending_events = Vec::with_capacity(pending_notifications.len());
        for notification_payload in pending_notifications {
            let event = append_event(
                stream,
                &stream_id,
                notification_payload.clone(),
                None,
                self.config.replay_window_limit,
            );
            pending_events.push(event);
        }
        // Serialise the inner JSON-RPC envelope (NOT the
        // `ProtocolResponse` Rust enum). The enum has external tagging
        // by default, which would emit `{"JsonRpcSuccess":{…}}` on
        // the SSE wire — clients then can't match the response's
        // `id` to their request and time out. The standard MCP
        // contract is the bare `{"jsonrpc":"2.0","id":…,"result":…}`
        // envelope; the variant tag is a Rust-internal detail.
        // `NotificationAccepted` should never reach this path (the
        // caller only streams successful protocol responses); we
        // still handle it defensively as an empty event.
        let response_payload = match protocol_response {
            ProtocolResponse::JsonRpcSuccess(success) => {
                serde_json::to_string(success).expect("protocol response serialized")
            }
            ProtocolResponse::JsonRpcError(error) => {
                serde_json::to_string(error).expect("protocol response serialized")
            }
            ProtocolResponse::NotificationAccepted => String::new(),
        };
        let response_event = append_event(
            stream,
            &stream_id,
            response_payload,
            None,
            self.config.replay_window_limit,
        );
        let mut events = vec![prime_event];
        if let Some(logging_event) = logging_event {
            events.push(logging_event);
        }
        events.extend(pending_events);
        events.push(response_event);
        let stored = session.clone();
        drop(session);
        self.persist_session(&stored);
        Ok(events)
    }

    fn stream_raw_message(
        &self,
        session_id: &str,
        message_json: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.stream_message_inner(session_id, message_json, None)
    }

    fn stream_delivery_message(
        &self,
        session_id: &str,
        message_json: &str,
        delivery_id: &str,
    ) -> Result<Vec<SseEventRecord>, StreamAccessError> {
        self.stream_message_inner(session_id, message_json, Some(delivery_id))
    }

    fn list_sessions(&self) -> Vec<SessionSnapshot> {
        self.sessions.iter().map(|e| e.value().snapshot()).collect()
    }

    fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ImplementationInfo, InitializeParams, SUPPORTED_PROTOCOL_VERSION};

    fn test_init_params() -> InitializeParams {
        InitializeParams {
            protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
            capabilities: Default::default(),
            client_info: ImplementationInfo {
                name: "test-client".to_owned(),
                title: None,
                version: "0.1.0".to_owned(),
                description: None,
                website_url: None,
                icons: None,
            },
        }
    }

    fn temp_data_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_path_buf();
        (dir, path)
    }

    #[test]
    fn in_memory_store_persists_negotiated_version_not_requested() {
        // Client may request a legacy version string. The runtime negotiates,
        // then the store MUST persist the negotiated value so later requests
        // operate on the agreed version.
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let mut params = test_init_params();
        params.protocol_version = "1999-01-01".to_owned();

        let snapshot = store.create_session(SUPPORTED_PROTOCOL_VERSION, &params);
        assert_eq!(snapshot.protocol_version, SUPPORTED_PROTOCOL_VERSION);

        let persisted = store
            .session_protocol_version(&snapshot.session_id)
            .expect("session exists");
        assert_eq!(persisted, SUPPORTED_PROTOCOL_VERSION);
    }

    fn ms_timeout_store() -> KvBackedSessionStore {
        // The real wired default: a 15-minute idle window expressed in ms.
        KvBackedSessionStore::new_in_memory(SessionStoreConfig {
            session_idle_timeout_ms: 900_000,
            ..Default::default()
        })
    }

    fn backdate_session(store: &KvBackedSessionStore, session_id: &str, age: chrono::Duration) {
        store
            .sessions
            .get_mut(session_id)
            .expect("session present")
            .last_seen_at = Utc::now() - age;
    }

    #[test]
    fn idle_session_pruned_with_realistic_ms_timeout() {
        let store = ms_timeout_store();
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        // Just past the 15-minute window: 900_001 ms >= the 900_000 ms idle
        // timeout, so the session must be pruned on the next access.
        backdate_session(&store, &id, chrono::Duration::milliseconds(900_001));
        let err = store
            .load_session(Some(&id), false)
            .expect_err("expired session must be pruned");
        assert!(matches!(err, SessionAccessError::UnknownSession));
    }

    #[test]
    fn fresh_session_survives_realistic_ms_timeout() {
        let store = ms_timeout_store();
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        assert!(store.load_session(Some(&id), false).is_ok());
    }

    #[test]
    fn session_just_under_ms_timeout_survives() {
        let store = ms_timeout_store();
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        backdate_session(&store, &id, chrono::Duration::milliseconds(899_000));
        assert!(store.load_session(Some(&id), false).is_ok());
    }

    #[test]
    fn event_id_helpers_parse_delivery_suffix() {
        // A plain stream event id has no delivery suffix.
        assert_eq!(event_id_core("stream-0:3"), "stream-0:3");
        assert_eq!(delivery_id_from_event_id("stream-0:3"), None);
        assert_eq!(parse_event_id("stream-0:3"), Some(("stream-0", 3)));

        // A delivery-tagged id: the canonical core parses identically and the
        // opaque delivery id is recoverable.
        let tagged = "stream-0:3@00000000000000000007-abc";
        assert_eq!(event_id_core(tagged), "stream-0:3");
        assert_eq!(parse_event_id(tagged), Some(("stream-0", 3)));
        assert_eq!(
            delivery_id_from_event_id(tagged),
            Some("00000000000000000007-abc")
        );
        // An empty suffix is treated as no ack.
        assert_eq!(delivery_id_from_event_id("stream-0:3@"), None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delivery_tagged_event_resumes_via_suffixed_cursor() {
        // A server-push streamed via `stream_delivery_message` carries an
        // opaque `@{delivery_id}` suffix on its event id. The client echoes
        // the whole id back as Last-Event-Id; resume must still locate the
        // record and replay only events AFTER it (the suffix must not break
        // same-replica reconnect).
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let session_id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        store
            .transition_session_to_operational(&session_id)
            .expect("transition");
        // Opening the stream allocates the active stream and a priming event.
        store
            .open_sse_stream(Some(&session_id), None)
            .expect("open stream");

        let delivery_id = "00000000000000000001-feedface";
        let delivered = store
            .stream_delivery_message(
                &session_id,
                r#"{"jsonrpc":"2.0","id":9,"result":{"ok":true}}"#,
                delivery_id,
            )
            .expect("delivery streamed");
        assert_eq!(delivered.len(), 1);
        // The wire event id carries the opaque suffix.
        assert!(delivered[0].event_id.ends_with(&format!("@{delivery_id}")));

        // Resume echoing the suffixed id: the record is found (not Expired)
        // and nothing after it exists, so the replay set is empty.
        let resume = crate::runtime::ResumeCursor {
            last_event_id: delivered[0].event_id.clone(),
        };
        let resumed = store
            .open_sse_stream(Some(&session_id), Some(&resume))
            .expect("resume must locate the delivery-tagged cursor");
        assert!(resumed.is_empty());
    }

    #[test]
    fn bind_session_owner_round_trips_via_snapshot() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        // A freshly created session has no owner until bound.
        assert!(
            store
                .load_session(Some(&id), false)
                .unwrap()
                .owner_principal
                .is_none()
        );
        store.bind_session_owner(&id, Some("alice"));
        assert_eq!(
            store
                .load_session(Some(&id), false)
                .unwrap()
                .owner_principal
                .as_deref(),
            Some("alice")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_creates_data_directory() {
        let parent = tempfile::tempdir().expect("temp dir");
        let data_dir = parent.path().join("sessions");
        assert!(!data_dir.exists());
        let _store =
            KvBackedSessionStore::new_with_file(SessionStoreConfig::default(), data_dir.clone())
                .await
                .expect("store created");
        assert!(data_dir.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_recovers_sessions_across_instances() {
        let (_dir, data_dir) = temp_data_dir();
        let session_id;

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
            session_id = snapshot.session_id.clone();
            store
                .transition_session_to_operational(&session_id)
                .expect("transition");
        }

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store
                .load_session(Some(&session_id), true)
                .expect("session recovered");
            assert_eq!(snapshot.session_id, session_id);
            assert_eq!(snapshot.phase, SessionPhase::Operational);
            assert_eq!(snapshot.protocol_version, SUPPORTED_PROTOCOL_VERSION);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kv_read_back_resolves_session_created_on_another_replica() {
        // Two replicas sharing ONE coordinator KV, both already running.
        // The session is created on A *after* B booted, so B can only
        // resolve it via read-back on a local miss (not boot hydration) —
        // the round-robin-LB scenario.
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let store_a = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store A");
        let store_b = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store B");

        let snapshot = store_a.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let session_id = snapshot.session_id.clone();
        store_a
            .transition_session_to_operational(&session_id)
            .expect("transition on A");

        // B never saw this session locally; the read path must hydrate it
        // from the shared KV instead of returning UnknownSession.
        let recovered = store_b
            .load_session(Some(&session_id), true)
            .expect("B resolves the session via KV read-back");
        assert_eq!(recovered.session_id, session_id);
        assert_eq!(recovered.phase, SessionPhase::Operational);
        assert_eq!(recovered.protocol_version, SUPPORTED_PROTOCOL_VERSION);
        assert_eq!(
            store_b.session_protocol_version(&session_id).as_deref(),
            Some(SUPPORTED_PROTOCOL_VERSION),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn kv_read_back_terminate_removes_shared_copy_cross_replica() {
        // A terminate that lands on a replica which never saw the session
        // must still delete the shared KV copy, so it can't resurrect via
        // read-back on a third replica.
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let store_a = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store A");
        let store_b = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store B");

        let snapshot = store_a.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let session_id = snapshot.session_id.clone();

        // B terminates a session it never saw locally → must clear KV.
        assert!(store_b.terminate_session(&session_id));

        // A fresh replica C (boot-hydrates from the shared KV) must not
        // find it, proving the KV copy is gone.
        let store_c = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store C");
        assert!(matches!(
            store_c.load_session(Some(&session_id), false),
            Err(SessionAccessError::UnknownSession)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_terminate_drops_session_across_instances() {
        let (_dir, data_dir) = temp_data_dir();
        let session_id = {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
            assert!(store.terminate_session(&snapshot.session_id));
            snapshot.session_id
        };

        let store =
            KvBackedSessionStore::new_with_file(SessionStoreConfig::default(), data_dir.clone())
                .await
                .expect("store created");
        let result = store.load_session(Some(&session_id), false);
        assert!(matches!(result, Err(SessionAccessError::UnknownSession)));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_recovers_stream_replay_state() {
        let (_dir, data_dir) = temp_data_dir();
        let session_id;
        let original_events;

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
            session_id = snapshot.session_id.clone();
            store
                .transition_session_to_operational(&session_id)
                .expect("transition");
            original_events = store
                .open_sse_stream(Some(&session_id), None)
                .expect("open stream");
            assert!(!original_events.is_empty());
        }

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store
                .load_session(Some(&session_id), true)
                .expect("session recovered");
            assert_eq!(snapshot.phase, SessionPhase::Operational);

            let resume = crate::runtime::ResumeCursor {
                last_event_id: original_events[0].event_id.clone(),
            };
            let resumed = store
                .open_sse_stream(Some(&session_id), Some(&resume))
                .expect("resume stream");
            assert_eq!(resumed.len(), original_events.len() - 1);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_log_level_persists() {
        let (_dir, data_dir) = temp_data_dir();
        let session_id;

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
            session_id = snapshot.session_id.clone();
            store
                .transition_session_to_operational(&session_id)
                .expect("transition");
            store
                .set_session_log_level(Some(&session_id), LoggingLevel::Debug)
                .expect("set log level");
        }

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store
                .load_session(Some(&session_id), true)
                .expect("session recovered");
            assert_eq!(snapshot.log_level, LoggingLevel::Debug);
        }
    }
}

#[cfg(test)]
mod session_limit_store_tests {
    use super::*;
    use crate::protocol::{ImplementationInfo, InitializeParams, SUPPORTED_PROTOCOL_VERSION};

    fn test_init_params() -> InitializeParams {
        InitializeParams {
            protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
            capabilities: Default::default(),
            client_info: ImplementationInfo {
                name: "test-client".to_owned(),
                title: None,
                version: "0.1.0".to_owned(),
                description: None,
                website_url: None,
                icons: None,
            },
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn file_backed_store_enforces_max_sessions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().to_path_buf();
        let store = KvBackedSessionStore::new_with_file(
            SessionStoreConfig {
                max_sessions: 2,
                ..Default::default()
            },
            data_dir,
        )
        .await
        .expect("store created");

        let snap1 = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(!snap1.session_id.is_empty(), "first session should succeed");

        let snap2 = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(
            !snap2.session_id.is_empty(),
            "second session should succeed"
        );

        let snap3 = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(
            snap3.session_id.is_empty(),
            "third session should be rejected"
        );
    }

    #[test]
    fn inmemory_store_enforces_max_sessions() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig {
            max_sessions: 1,
            ..Default::default()
        });

        let snap1 = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(!snap1.session_id.is_empty(), "first session should succeed");

        let snap2 = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(
            snap2.session_id.is_empty(),
            "second session should be rejected"
        );
    }

    #[test]
    fn create_session_with_id_uses_the_supplied_id_and_is_idempotent() {
        // Modern stateless mode derives a deterministic id per principal;
        // the store must honour it and converge on one session for repeat
        // calls (concurrent cross-replica creates of the same id).
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let sid = "mcpg-m-deadbeef";
        let snap1 =
            store.create_session_with_id(sid, SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert_eq!(snap1.session_id, sid, "must use the caller-supplied id");

        // A second call with the same id returns the SAME session, not a new
        // one — so two replicas racing the same deterministic id agree.
        let snap2 =
            store.create_session_with_id(sid, SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert_eq!(snap2.session_id, sid);
        assert_eq!(
            snap1.created_at, snap2.created_at,
            "idempotent create must not mint a fresh session"
        );

        // And it is loadable by that id (the cross-replica read path).
        assert!(store.load_session(Some(sid), false).is_ok());
    }

    #[test]
    fn idle_eviction_forwards_the_session_id_to_the_notifier() {
        // A session the client never terminates is dropped by idle expiry; the
        // runtime cleanup cascade needs that id, so the store must forward it
        // on the eviction channel.
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig {
            session_idle_timeout_ms: 1,
            ..SessionStoreConfig::default()
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        store.set_eviction_notifier(tx);

        let snap = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let sid = snap.session_id.clone();
        assert!(store.contains_active_session(&sid));

        std::thread::sleep(std::time::Duration::from_millis(5));
        store.evict_if_expired(&sid); // lazy per-access idle expiry
        assert!(
            !store.contains_active_session(&sid),
            "the idle session must be evicted"
        );
        assert_eq!(
            rx.try_recv().ok().as_deref(),
            Some(sid.as_str()),
            "the evicted id must be forwarded to the runtime cascade"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn legacy_create_session_is_create_once_against_shared_kv() {
        // RF-4: the legacy create persists with `put_if_absent`, so a live row
        // already in the shared KV under the same id is never clobbered by a
        // re-create. Pre-seed the KV with a session whose phase has advanced,
        // then drive a second replica's create at the SAME id — the seeded
        // row must survive (last-writer-wins would have reset it).
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let store_a = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store A");

        let snap = store_a.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let sid = snap.session_id.clone();
        store_a
            .transition_session_to_operational(&sid)
            .expect("advance A's session phase");

        // A second replica that has the SAME id in its working set (e.g. it
        // minted an identical id, the pathological create-once case) must not
        // overwrite the live shared row with a fresh AwaitingInitialized one.
        let live = store_a.load_session(Some(&sid), false).expect("A live");
        assert_eq!(live.phase, SessionPhase::Operational);

        let store_b = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store B");
        // Force B to attempt a create-once write for the existing id by
        // round-tripping through the create-once persister directly.
        let now = Utc::now();
        let clobber = StoredSession {
            session_id: sid.clone(),
            protocol_version: SUPPORTED_PROTOCOL_VERSION.to_owned(),
            client_info: test_init_params().client_info,
            client_capabilities: test_init_params().capabilities,
            phase: SessionPhase::AwaitingInitialized,
            log_level: LoggingLevel::Info,
            next_stream_ordinal: 0,
            streams: HashMap::new(),
            active_stream_id: None,
            owner_principal: None,
            last_seen_at: now,
            created_at: now,
        };
        let wrote = store_b.persist_session_create_once(&clobber);
        assert!(!wrote, "create-once must lose to the live shared row");

        // The shared row still reflects A's advanced phase.
        let store_c = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store C");
        let recovered = store_c.load_session(Some(&sid), false).expect("C resolves");
        assert_eq!(recovered.phase, SessionPhase::Operational);
    }
}
