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

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// A client or an operator ended the session.
    Terminated,
    /// No replica used the session for the idle timeout.
    IdleExpired,
}

impl SessionEndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminated => "terminated",
            Self::IdleExpired => "idle_expired",
        }
    }

    fn parse(value: &[u8]) -> Self {
        if value == Self::IdleExpired.as_str().as_bytes() {
            Self::IdleExpired
        } else {
            Self::Terminated
        }
    }
}

/// A session that ended, as this replica saw it end.
#[derive(Debug, Clone)]
pub struct EndedSession {
    pub session_id: String,
    pub reason: SessionEndReason,
    /// This replica recorded the end, once for every replica that shares the
    /// store: it runs the cleanup they share and tells the others.
    pub recorded: bool,
    /// The copy of the session this replica held, if it held one.
    pub snapshot: Option<SessionSnapshot>,
}

/// Held by a long-lived stream of a session; [`Self::ended`] completes when
/// the session ends on this replica.
pub struct SessionLifetime {
    token: tokio_util::sync::CancellationToken,
    registration: LifetimeRegistration,
}

impl SessionLifetime {
    /// Completes when the session ends here. The stream that awaits it keeps
    /// its registration, so the store can find it until then.
    pub async fn ended(self) {
        let _registration = self.registration;
        self.token.cancelled().await;
    }
}

/// The streams of one session on this replica: a token every stream of the
/// session waits on, and how many streams wait.
#[derive(Debug)]
struct Lifetime {
    created_at: DateTime<Utc>,
    token: tokio_util::sync::CancellationToken,
    streams: usize,
}

type Lifetimes = std::sync::Arc<dashmap::DashMap<String, Lifetime>>;

/// One stream's place in [`Lifetimes`]; the last stream of a session to go
/// removes the session's entry.
struct LifetimeRegistration {
    lifetimes: Lifetimes,
    session_id: String,
    created_at: DateTime<Utc>,
}

impl Drop for LifetimeRegistration {
    fn drop(&mut self) {
        use dashmap::mapref::entry::Entry;
        if let Entry::Occupied(mut entry) = self.lifetimes.entry(self.session_id.clone())
            && entry.get().created_at == self.created_at
        {
            let lifetime = entry.get_mut();
            lifetime.streams = lifetime.streams.saturating_sub(1);
            if lifetime.streams == 0 {
                entry.remove();
            }
        }
    }
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
    /// End `session_id`; `None` when no session lives under it.
    fn terminate_session(&self, session_id: &str) -> Option<EndedSession>;
    /// Register a sink told of every session that ends without a
    /// `terminate_session` call: one idle on every replica, and one this
    /// replica finds another replica ended. Lets the runtime run its
    /// per-session cleanup for them. Default no-op (in-process test stores
    /// need no cleanup).
    fn set_end_notifier(&self, notifier: tokio::sync::mpsc::UnboundedSender<EndedSession>) {
        let _ = notifier;
    }
    /// Drop this replica's copy of the session that began at `created_at`
    /// under `session_id`, which another replica ended, and end its streams
    /// here. Returns the dropped copy.
    fn drop_ended_session(
        &self,
        session_id: &str,
        created_at: DateTime<Utc>,
    ) -> Option<SessionSnapshot> {
        let _ = (session_id, created_at);
        None
    }
    /// What a long-lived stream of `session_id` waits on to end with the
    /// session; `None` when this replica holds no copy of it.
    fn session_lifetime(&self, session_id: &str) -> Option<SessionLifetime> {
        let _ = session_id;
        None
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
    /// Whether `session_id` is in use anywhere: held here and not idle, or
    /// not idle in the row other replicas and later processes read. `None`
    /// when this store cannot answer for every replica.
    fn session_alive(&self, session_id: &str) -> Option<bool> {
        let _ = session_id;
        None
    }
    /// Count `session_id` toward the live sessions of its owner (bound with
    /// [`Self::bind_session_owner`]), unless the owner already has `cap`
    /// live sessions on any replica. `None` when this store keeps no count
    /// that every replica shares: the runtime counts its own sessions then.
    fn claim_tenant_slot(&self, session_id: &str, cap: usize) -> Option<bool> {
        let _ = (session_id, cap);
        None
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
    /// The session counts toward its owner's `max_sessions_per_tenant`
    /// in the fleet: its tenant slot row lives as long as its row.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    tenant_slot: bool,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    /// When this replica last wrote the row (Unix ms); not persisted.
    #[serde(skip)]
    written_at_ms: i64,
    /// When this replica last looked for an end of the session another
    /// replica recorded (Unix ms); not persisted.
    #[serde(skip)]
    verified_at_ms: i64,
}

/// The tenant a session counts toward: its owner, or `anonymous`.
fn tenant_of(session: &StoredSession) -> &str {
    session.owner_principal.as_deref().unwrap_or("anonymous")
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

    /// Drop the replay of the oldest streams while more than
    /// [`RETAINED_STREAMS`] are kept or their events hold more than
    /// [`RETAINED_REPLAY_BYTES`]; the active stream stays.
    fn retire_old_streams(&mut self) {
        let mut ids: Vec<(u64, String)> = self
            .streams
            .keys()
            .map(|id| (stream_ordinal(id).unwrap_or(0), id.clone()))
            .collect();
        ids.sort_unstable();
        let mut kept = ids.len();
        let mut bytes: usize = self.streams.values().map(StoredStream::replay_bytes).sum();
        for (_, id) in ids {
            if kept <= RETAINED_STREAMS && bytes <= RETAINED_REPLAY_BYTES {
                break;
            }
            if self.active_stream_id.as_deref() == Some(id.as_str()) {
                continue;
            }
            if let Some(stream) = self.streams.remove(&id) {
                kept -= 1;
                bytes -= stream.replay_bytes();
            }
        }
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

impl StoredStream {
    /// The bytes of event data the replay holds.
    fn replay_bytes(&self) -> usize {
        self.replay_window
            .iter()
            .map(|event| event.event_id.len() + event.data.len())
            .sum()
    }
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

/// The streams a session keeps the replay of: its most recent ones. A client
/// resumes a stream it was cut from, not one it finished long ago; every
/// request opens a stream, so without a bound the row grows at each one.
const RETAINED_STREAMS: usize = 16;

/// The most event data a session's replay keeps, in bytes: the oldest
/// streams go first. A response stream holds its whole result, and a row
/// must stay well under a coordinator's message limit (NATS: 1 MiB).
const RETAINED_REPLAY_BYTES: usize = 256 * 1024;

/// The ordinal of a `stream-{ordinal}` id.
fn stream_ordinal(stream_id: &str) -> Option<u64> {
    stream_id.strip_prefix("stream-")?.parse().ok()
}

/// How often a read refreshes the row of a session in use: a quarter of
/// the idle timeout, at least a second.
fn refresh_interval(session_idle_timeout_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis((session_idle_timeout_ms / 4).max(1_000))
}

/// How long a session row lives after its last write: the idle timeout and
/// two refresh intervals, so a row never expires before the session it
/// holds is idle.
fn row_ttl(session_idle_timeout_ms: u64) -> std::time::Duration {
    std::time::Duration::from_millis(session_idle_timeout_ms)
        + refresh_interval(session_idle_timeout_ms) * 2
}

/// How often a copy in use looks for an end another replica recorded, should
/// the word of it not have come: the refresh interval, at most 30 s.
fn verify_interval(session_idle_timeout_ms: u64) -> std::time::Duration {
    refresh_interval(session_idle_timeout_ms).min(std::time::Duration::from_secs(30))
}

/// What the shared row says of a session this replica's copy holds idle.
enum SharedRow {
    /// Another replica keeps the session in use.
    Live(StoredSession),
    /// No replica can still be using it.
    Ended,
    /// The store did not answer.
    Unknown,
}

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
/// serialises the [`StoredSession`] to KV, and a read refreshes the row at
/// most once per [`refresh_interval`], so the shared `last_seen_at` of a
/// session in use stays within that interval of the truth. A row lives
/// [`row_ttl`] after its last write. A local miss reads the row back (a
/// restart, or a session another replica created).
///
/// A local copy that looks idle may be stale: another replica can be
/// serving the session. In a shared store the copy is then replaced by the
/// shared row; only a session idle in the shared row too expires — its row
/// is deleted and the runtime's cleanup cascade runs.
///
/// When replicas share the store, the replica that ends a session records
/// the end under a key of its own beside the row, before it deletes the
/// row; of replicas that end it at once, the one that records the end runs
/// the cleanup they share. A copy in use here looks for that record at
/// most once per [`verify_interval`], and a row is read back only when no
/// end is recorded for it, so a replica that misses the word of an end
/// stops serving the session within that interval, and a row a replica
/// writes after the end cannot bring the session back.
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
    /// The long-lived streams of each session on this replica, ended with it.
    lifetimes: Lifetimes,
    /// Epoch-ms of the last full idle sweep; throttles `maybe_sweep`.
    last_pruned: std::sync::atomic::AtomicI64,
    /// Registered once (by the runtime at boot) to hear of every session
    /// that ends without a `terminate_session` call, which runs the runtime's
    /// cleanup itself. `None` until registered / in tests.
    end_tx: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<EndedSession>>,
    /// Other replicas write the same KV, so a local copy can lag the shared
    /// row ([`Self::shared_across_replicas`]).
    shared: bool,
    /// Every replica's sessions are in this store's KV, so it can tell a
    /// session that ended from one another replica serves
    /// ([`Self::fleet_visible`]).
    fleet_visible: bool,
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
            lifetimes: Lifetimes::default(),
            last_pruned: std::sync::atomic::AtomicI64::new(0),
            end_tx: std::sync::OnceLock::new(),
            shared: false,
            fleet_visible: true,
        }
    }

    /// Mark the KV as shared with other replicas. A local copy still awaiting
    /// `notifications/initialized` then checks the shared row's phase on each
    /// access, since another replica may have taken the notification.
    #[must_use]
    pub fn shared_across_replicas(mut self, shared: bool) -> Self {
        self.shared = shared;
        self
    }

    /// Whether this store's KV holds every replica's sessions. A replica
    /// with a store of its own in a fleet sees only its sessions, so it
    /// cannot say that a session of another replica ended.
    #[must_use]
    pub fn fleet_visible(mut self, visible: bool) -> Self {
        self.fleet_visible = visible;
        self
    }

    /// Tell the runtime of a session that ended without a
    /// `terminate_session` call, if a notifier is registered. Non-blocking;
    /// a closed channel is ignored.
    fn notify_ended(&self, ended: EndedSession) {
        if let Some(tx) = self.end_tx.get() {
            let _ = tx.send(ended);
        }
    }

    /// Other replicas serve and end the sessions of this store too.
    fn fleet_shared(&self) -> bool {
        self.shared && self.fleet_visible
    }

    fn age_ms(session: &StoredSession) -> u64 {
        (Utc::now() - session.last_seen_at)
            .num_milliseconds()
            .max(0) as u64
    }

    fn is_idle(&self, session: &StoredSession) -> bool {
        Self::age_ms(session) >= self.config.session_idle_timeout_ms
    }

    /// Whether no replica can still be using the session the shared `row`
    /// holds. A replica writes the touch of a session in use at most once per
    /// refresh interval, so in a store other replicas write, the row can lag
    /// that long behind the replica that serves the session.
    fn idle_everywhere(&self, row: &StoredSession) -> bool {
        let lag = if self.fleet_shared() {
            self.refresh_interval_ms() as u64
        } else {
            0
        };
        Self::age_ms(row) >= self.config.session_idle_timeout_ms + lag
    }

    /// What the shared row says of `session_id`, whose copy is idle here.
    fn shared_row(&self, session_id: &str) -> SharedRow {
        if !self.fleet_shared() {
            return SharedRow::Ended;
        }
        let key = Self::session_key(session_id);
        let value = match Self::block(async { self.state.get(&key).await }) {
            Ok(Some(value)) => value,
            Ok(None) => return SharedRow::Ended,
            Err(_) => return SharedRow::Unknown,
        };
        let Ok(mut row) = serde_json::from_slice::<StoredSession>(&value.bytes) else {
            return SharedRow::Ended;
        };
        if self.idle_everywhere(&row)
            || matches!(self.recorded_end(session_id, row.created_at), Ok(Some(_)))
        {
            return SharedRow::Ended;
        }
        row.verified_at_ms = Utc::now().timestamp_millis();
        SharedRow::Live(row)
    }

    /// End `session`, whose copy this replica no longer holds: record the
    /// end for every replica that shares the store, delete the session's
    /// rows unless `keep_rows` (a later session under its id has taken
    /// them), and end its streams here. Returns whether this call recorded
    /// the end.
    fn end_session(
        &self,
        session: &StoredSession,
        reason: SessionEndReason,
        keep_rows: bool,
    ) -> bool {
        let recorded = !self.fleet_shared() || {
            let key = Self::end_key(&session.session_id, session.created_at);
            let marker = bytes::Bytes::from_static(reason.as_str().as_bytes());
            let ttl = self.row_ttl();
            // A claim the store did not answer counts as won: the cleanup the
            // replicas share then runs twice rather than not at all.
            Self::block(async { self.state.put_if_absent(&key, marker, Some(ttl)).await })
                .unwrap_or(true)
        };
        if !keep_rows {
            self.remove_session(session);
        }
        self.end_streams(&session.session_id, session.created_at);
        recorded
    }

    /// End a session that is idle here and in the shared row, and tell the
    /// runtime.
    fn expire_session(&self, session: &StoredSession, keep_rows: bool) {
        let reason = SessionEndReason::IdleExpired;
        let recorded = self.end_session(session, reason, keep_rows);
        self.notify_ended(EndedSession {
            session_id: session.session_id.clone(),
            reason,
            recorded,
            snapshot: Some(session.snapshot()),
        });
    }

    /// Lazy per-entry expiry: atomically evict `session_id` iff it is still
    /// idle-expired (the `remove_if` predicate re-checks under the shard lock,
    /// so a concurrent `touch()` can't be clobbered). O(1); replaces the old
    /// per-request O(N) whole-map scan. A copy that is idle here while
    /// another replica keeps the session in use takes the shared row
    /// instead; one the store cannot tell about stays.
    fn evict_if_expired(&self, session_id: &str) {
        let Some(created_at) = self
            .sessions
            .get(session_id)
            .filter(|s| self.is_idle(s))
            .map(|s| s.created_at)
        else {
            return;
        };
        let keep_rows = match self.shared_row(session_id) {
            SharedRow::Unknown => return,
            SharedRow::Live(mut row) if row.created_at == created_at => {
                // Every caller uses the session now; untouched, the row can
                // still look idle here, and the sweep would drop it again.
                row.touch();
                self.sessions.insert(session_id.to_owned(), row);
                return;
            }
            SharedRow::Live(_) => true,
            SharedRow::Ended => false,
        };
        let removed = self.sessions.remove_if(session_id, |_, s| {
            self.is_idle(s) && s.created_at == created_at
        });
        if let Some((_, session)) = removed {
            self.expire_session(&session, keep_rows);
        }
    }

    /// Throttled full idle sweep: at most once per timeout window (capped at
    /// 60s), expire the idle sessions. Piggybacks on request traffic — the
    /// common path is a single atomic load + early return; the scan of the
    /// working set runs rarely, so never-reaccessed sessions are still
    /// reaped without an O(N) scan on the hot path. A session another
    /// replica keeps in use only leaves this replica's working set, and one
    /// the store cannot tell about stays.
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
        let idle: Vec<(String, DateTime<Utc>)> = self
            .sessions
            .iter()
            .filter(|entry| self.is_idle(entry.value()))
            .map(|entry| (entry.key().clone(), entry.value().created_at))
            .collect();
        for (session_id, created_at) in idle {
            let still_idle =
                |_: &String, s: &StoredSession| self.is_idle(s) && s.created_at == created_at;
            match self.shared_row(&session_id) {
                SharedRow::Unknown => {}
                SharedRow::Live(row) if row.created_at == created_at => {
                    self.sessions.remove_if(&session_id, still_idle);
                }
                row => {
                    let keep_rows = matches!(row, SharedRow::Live(_));
                    if let Some((_, session)) = self.sessions.remove_if(&session_id, still_idle) {
                        self.expire_session(&session, keep_rows);
                    }
                }
            }
        }
    }

    /// The key that records the end of the session that began at
    /// `created_at` under `session_id`; a later session under the same id
    /// has a key of its own.
    fn end_key(session_id: &str, created_at: DateTime<Utc>) -> String {
        format!("session-end:{session_id}:{}", created_at.timestamp_micros())
    }

    /// The end recorded for the session that began at `created_at` under
    /// `session_id`, if one is.
    fn recorded_end(
        &self,
        session_id: &str,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SessionEndReason>, mcpg_cluster_api::ClusterError> {
        let key = Self::end_key(session_id, created_at);
        Self::block(async { self.state.get(&key).await })
            .map(|entry| entry.map(|entry| SessionEndReason::parse(&entry.bytes)))
    }

    /// End the streams this replica holds of the session that began at
    /// `created_at`.
    fn end_streams(&self, session_id: &str, created_at: DateTime<Utc>) {
        if let Some((_, lifetime)) = self
            .lifetimes
            .remove_if(session_id, |_, lifetime| lifetime.created_at == created_at)
        {
            lifetime.token.cancel();
        }
    }

    /// Whether this replica holds a copy of the session that began at
    /// `created_at` under `session_id`.
    fn holds_copy(&self, session_id: &str, created_at: DateTime<Utc>) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|s| s.created_at == created_at)
    }

    /// Delete the rows of `session`, which ended after this replica may have
    /// written them, unless a later session under its id holds the row.
    fn remove_ended_rows(&self, session: &StoredSession) {
        let key = Self::session_key(&session.session_id);
        let taken = match Self::block(async { self.state.get(&key).await }) {
            Ok(Some(value)) => serde_json::from_slice::<StoredSession>(&value.bytes)
                .is_ok_and(|row| row.created_at != session.created_at),
            _ => false,
        };
        if !taken {
            self.remove_session(session);
        }
    }

    /// Drop this replica's copy of the session that began at `created_at`,
    /// whose end another replica recorded, with the rows this replica wrote
    /// after that end; end its streams here.
    fn drop_ended_copy(
        &self,
        session_id: &str,
        created_at: DateTime<Utc>,
    ) -> Option<StoredSession> {
        let dropped = self
            .sessions
            .remove_if(session_id, |_, s| s.created_at == created_at)
            .map(|(_, session)| session);
        if let Some(session) = &dropped {
            self.remove_ended_rows(session);
        }
        self.end_streams(session_id, created_at);
        dropped
    }

    /// Look for an end of this replica's copy of `session_id` that another
    /// replica recorded, at most once per [`verify_interval`], and drop the
    /// copy when one is: the word of an end can be lost on its way here.
    fn verify_copy(&self, session_id: &str) {
        if !self.fleet_shared() {
            return;
        }
        let now_ms = Utc::now().timestamp_millis();
        let interval = verify_interval(self.config.session_idle_timeout_ms).as_millis() as i64;
        let due = |copy: &StoredSession| now_ms - copy.verified_at_ms >= interval;
        // Most accesses find no check due; they take the read lock only.
        if !self.sessions.get(session_id).is_some_and(|copy| due(&copy)) {
            return;
        }
        let created_at = {
            let Some(mut copy) = self.sessions.get_mut(session_id) else {
                return;
            };
            if !due(&copy) {
                return;
            }
            // Claimed before the read, so concurrent requests read once.
            copy.verified_at_ms = now_ms;
            copy.created_at
        };
        if let Ok(Some(reason)) = self.recorded_end(session_id, created_at)
            && let Some(session) = self.drop_ended_copy(session_id, created_at)
        {
            self.notify_ended(EndedSession {
                session_id: session_id.to_owned(),
                reason,
                recorded: false,
                snapshot: Some(session.snapshot()),
            });
        }
    }

    pub async fn new(
        config: SessionStoreConfig,
        state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    ) -> anyhow::Result<Self> {
        // No hydration: a local miss reads the row back, and a row expires
        // with its TTL.
        Ok(Self {
            config,
            state,
            sessions: dashmap::DashMap::new(),
            lifetimes: Lifetimes::default(),
            last_pruned: std::sync::atomic::AtomicI64::new(0),
            end_tx: std::sync::OnceLock::new(),
            shared: false,
            fleet_visible: true,
        })
    }

    /// Convenience constructor over a `FileKv` rooted at `data_dir`.
    /// Surviving sessions read back from disk on first use.
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

    /// The rows of `tenant`'s counted sessions, one per session.
    fn tenant_slot_prefix(tenant: &str) -> String {
        use base64::Engine;
        format!(
            "session-t:{}:",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tenant.as_bytes())
        )
    }

    /// The tenant slot row of `session`, when it counts toward its owner.
    fn tenant_slot_key(session: &StoredSession) -> Option<String> {
        session.tenant_slot.then(|| {
            format!(
                "{}{}",
                Self::tenant_slot_prefix(tenant_of(session)),
                session.session_id
            )
        })
    }

    fn block<F, T>(fut: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        super::block_on_store(fut)
    }

    /// How long a row lives after its last write.
    fn row_ttl(&self) -> std::time::Duration {
        row_ttl(self.config.session_idle_timeout_ms)
    }

    /// How often a read refreshes the row of a session in use.
    fn refresh_interval_ms(&self) -> i64 {
        refresh_interval(self.config.session_idle_timeout_ms).as_millis() as i64
    }

    /// Record that this replica wrote the row of `session_id` at `at_ms`.
    fn mark_written(&self, session_id: &str, at_ms: i64) {
        if let Some(mut live) = self.sessions.get_mut(session_id) {
            live.written_at_ms = live.written_at_ms.max(at_ms);
        }
    }

    /// Write the row of `session`, and its tenant slot row with the same
    /// TTL; returns whether the row was written. A session that ended here
    /// while the row was written takes the row with it.
    fn persist_session(&self, session: &StoredSession) -> bool {
        let key = Self::session_key(&session.session_id);
        let bytes = match serde_json::to_vec(session) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let payload = bytes::Bytes::from(bytes);
        let row_bytes = payload.len();
        let at_ms = Utc::now().timestamp_millis();
        let ttl = self.row_ttl();
        let slot = Self::tenant_slot_key(session);
        let outcome = Self::block(async {
            let outcome = self.state.put(&key, payload, Some(ttl)).await;
            if outcome.is_ok()
                && let Some(slot) = &slot
            {
                let _ = self
                    .state
                    .put(slot, bytes::Bytes::from_static(b"1"), Some(ttl))
                    .await;
            }
            outcome
        });
        let written = match outcome {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    session_id = %session.session_id,
                    row_bytes,
                    %error,
                    "session row write failed; other replicas read the last copy written"
                );
                false
            }
        };
        if written {
            self.mark_written(&session.session_id, at_ms);
            // An end removes the copy before it deletes the row, so a write
            // that lands after the delete finds the copy gone.
            if !self.holds_copy(&session.session_id, session.created_at) {
                self.remove_ended_rows(session);
            }
        }
        written
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
        let ttl = self.row_ttl();
        Self::block(async { self.state.put_if_absent(&key, payload, Some(ttl)).await })
            .unwrap_or(false)
    }

    fn remove_session(&self, session: &StoredSession) {
        let key = Self::session_key(&session.session_id);
        let slot = Self::tenant_slot_key(session);
        let _ = Self::block(async {
            if let Some(slot) = &slot {
                let _ = self.state.delete(slot).await;
            }
            self.state.delete(&key).await
        });
    }

    /// Cross-replica / post-failover session continuity: if `session_id`
    /// is absent from the in-memory working set, read it back from the
    /// shared KV and insert it, so a session created on another replica
    /// (or before a restart) resolves here instead of 404'ing.
    ///
    /// No KV round-trip when the session is already local and operational
    /// (the sticky-session / same-replica happy path); in a shared store, a
    /// local copy still awaiting `notifications/initialized` checks the
    /// shared row's phase ([`Self::adopt_shared_phase`]). The `sessions`
    /// lock is held only for the membership check and the final insert,
    /// never across the (blocking) KV read. Mirrors `new()`'s boot-hydrate
    /// idle-timeout check so a read-back behaves identically to a restart
    /// hydrate.
    fn ensure_hydrated(&self, session_id: &str) {
        if self.sessions.contains_key(session_id) {
            self.adopt_shared_phase(session_id);
            self.verify_copy(session_id);
            return;
        }
        let key = Self::session_key(session_id);
        let value = match Self::block(async { self.state.get(&key).await }) {
            Ok(Some(v)) => v,
            // KV miss or backend error → leave absent; the caller's
            // existing `ok_or(UnknownSession)` handles it.
            _ => return,
        };
        let mut session: StoredSession = match serde_json::from_slice(&value.bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        // A row no replica can still be using is absent; its TTL removes it.
        if self.idle_everywhere(&session) {
            return;
        }
        // A row written after its session ended does not bring it back.
        if self.fleet_shared()
            && matches!(
                self.recorded_end(session_id, session.created_at),
                Ok(Some(_))
            )
        {
            return;
        }
        session.verified_at_ms = Utc::now().timestamp_millis();
        // `or_insert` (not overwrite): if a concurrent request hydrated
        // or created the same id while we read KV, keep the live copy.
        self.sessions
            .entry(session.session_id.clone())
            .or_insert(session);
    }

    /// A session's phase only moves forward, and the replica that takes
    /// `notifications/initialized` need not be the one that created the
    /// session: a local copy still awaiting it adopts the shared row's
    /// `Operational`. One KV read per call, and only while the local copy
    /// awaits `notifications/initialized`.
    fn adopt_shared_phase(&self, session_id: &str) {
        if !self.shared {
            return;
        }
        let awaiting = self
            .sessions
            .get(session_id)
            .is_some_and(|s| s.phase == SessionPhase::AwaitingInitialized);
        if !awaiting {
            return;
        }
        let key = Self::session_key(session_id);
        let Ok(Some(value)) = Self::block(async { self.state.get(&key).await }) else {
            return;
        };
        let Ok(shared) = serde_json::from_slice::<StoredSession>(&value.bytes) else {
            return;
        };
        if shared.phase == SessionPhase::Operational
            && let Some(mut local) = self.sessions.get_mut(session_id)
        {
            local.phase = SessionPhase::Operational;
        }
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
        let mut session = StoredSession {
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
            tenant_slot: false,
            last_seen_at: now,
            created_at: now,
            written_at_ms: 0,
            verified_at_ms: now.timestamp_millis(),
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
        if self.persist_session_create_once(&session) {
            session.written_at_ms = now.timestamp_millis();
        }
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
            tenant_slot: false,
            last_seen_at: now,
            created_at: now,
            written_at_ms: 0,
            verified_at_ms: now.timestamp_millis(),
        };
        self.maybe_sweep();
        if let Some(rejection) =
            check_session_limit(&self.sessions, &self.config, &session.protocol_version)
        {
            return rejection;
        }
        // The copy goes in before the row is written: a row whose copy is gone
        // belongs to an ended session. A concurrent create under the same id
        // that went in first wins.
        let (snapshot, stored) = {
            let copy = self
                .sessions
                .entry(session.session_id.clone())
                .or_insert(session);
            (copy.snapshot(), copy.clone())
        };
        self.persist_session(&stored);
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
        // A read bumps `last_seen_at` in memory, and writes the row at most
        // once per refresh interval: a blocking KV write on EVERY request
        // would thrash the tokio worker pool under load, and the shared
        // `last_seen_at` only has to stay fresh enough that no replica takes
        // a session in use for idle.
        let snapshot = session.snapshot();
        let now_ms = Utc::now().timestamp_millis();
        if now_ms - session.written_at_ms >= self.refresh_interval_ms() {
            // Claimed before the write, so concurrent reads write once.
            session.written_at_ms = now_ms;
            let stored = session.clone();
            drop(session);
            self.persist_session(&stored);
        }
        Ok(snapshot)
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

    fn terminate_session(&self, session_id: &str) -> Option<EndedSession> {
        // Hydrate first so a DELETE/terminate that lands on a replica
        // which never saw the session still removes the shared KV copy —
        // otherwise the session would resurrect via read-back elsewhere.
        self.ensure_hydrated(session_id);
        let (_, session) = self.sessions.remove(session_id)?;
        let reason = SessionEndReason::Terminated;
        let recorded = self.end_session(&session, reason, false);
        Some(EndedSession {
            session_id: session.session_id.clone(),
            reason,
            recorded,
            snapshot: Some(session.snapshot()),
        })
    }

    fn set_end_notifier(&self, notifier: tokio::sync::mpsc::UnboundedSender<EndedSession>) {
        let _ = self.end_tx.set(notifier);
    }

    fn drop_ended_session(
        &self,
        session_id: &str,
        created_at: DateTime<Utc>,
    ) -> Option<SessionSnapshot> {
        self.drop_ended_copy(session_id, created_at)
            .map(|session| session.snapshot())
    }

    fn session_lifetime(&self, session_id: &str) -> Option<SessionLifetime> {
        // The copy's shard stays locked while the stream registers, so an end
        // that removes the copy finds the registration when it ends the
        // streams.
        let copy = self.sessions.get(session_id)?;
        let created_at = copy.created_at;
        let token = {
            let mut lifetime = self
                .lifetimes
                .entry(session_id.to_owned())
                .or_insert_with(|| Lifetime {
                    created_at,
                    token: tokio_util::sync::CancellationToken::new(),
                    streams: 0,
                });
            if lifetime.created_at != created_at {
                // The streams of an earlier session under this id outlived it.
                lifetime.token.cancel();
                *lifetime = Lifetime {
                    created_at,
                    token: tokio_util::sync::CancellationToken::new(),
                    streams: 0,
                };
            }
            lifetime.streams += 1;
            lifetime.token.clone()
        };
        drop(copy);
        Some(SessionLifetime {
            token,
            registration: LifetimeRegistration {
                lifetimes: std::sync::Arc::clone(&self.lifetimes),
                session_id: session_id.to_owned(),
                created_at,
            },
        })
    }

    fn contains_active_session(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    fn claim_tenant_slot(&self, session_id: &str, cap: usize) -> Option<bool> {
        if !self.fleet_shared() {
            return None;
        }
        self.ensure_hydrated(session_id);
        let tenant = tenant_of(&*self.sessions.get(session_id)?).to_owned();
        let prefix = Self::tenant_slot_prefix(&tenant);
        let slot = format!("{prefix}{session_id}");
        let ttl = self.row_ttl();
        // Write the slot, then count: of sessions that claim at once, the
        // one that counts last sees every other's slot, so the tenant never
        // holds more than `cap`. Two that see each other both give up.
        let claimed = Self::block(async {
            self.state
                .put(&slot, bytes::Bytes::from_static(b"1"), Some(ttl))
                .await?;
            let live = self
                .state
                .list_prefix(&prefix, cap.saturating_add(1))
                .await?;
            if live.len() > cap {
                self.state.delete(&slot).await?;
                return Ok::<bool, mcpg_cluster_api::ClusterError>(false);
            }
            Ok(true)
        });
        match claimed {
            Ok(true) => {
                let stored = {
                    let mut session = self.sessions.get_mut(session_id)?;
                    session.tenant_slot = true;
                    session.clone()
                };
                self.persist_session(&stored);
                Some(true)
            }
            Ok(false) => Some(false),
            Err(error) => {
                tracing::warn!(
                    session_id,
                    %error,
                    "tenant session count unavailable; this replica counts its own sessions"
                );
                None
            }
        }
    }

    fn session_alive(&self, session_id: &str) -> Option<bool> {
        if !self.fleet_visible {
            return None;
        }
        if self
            .sessions
            .get(session_id)
            .is_some_and(|s| !self.is_idle(&s))
        {
            return Some(true);
        }
        let key = Self::session_key(session_id);
        let row = match Self::block(async { self.state.get(&key).await }) {
            Ok(Some(value)) => serde_json::from_slice::<StoredSession>(&value.bytes).ok()?,
            Ok(None) => return Some(false),
            Err(_) => return None,
        };
        if self.idle_everywhere(&row) {
            return Some(false);
        }
        if !self.fleet_shared() {
            return Some(true);
        }
        self.recorded_end(session_id, row.created_at)
            .ok()
            .map(|end| end.is_none())
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
            let Some(stream) = session.streams.get(stream_id) else {
                // A stream the session opened and has since retired.
                let retired = stream_ordinal(stream_id)
                    .is_some_and(|ordinal| ordinal < session.next_stream_ordinal);
                return Err(if retired {
                    StreamAccessError::ExpiredCursor
                } else {
                    StreamAccessError::InvalidCursor
                });
            };
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
        session.retire_old_streams();
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
        session.retire_old_streams();
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
    async fn initialized_on_one_replica_is_operational_on_the_one_that_created_it() {
        // Round-robin without affinity: `initialize` lands on A,
        // `notifications/initialized` on B, the next call on A again. A's own
        // copy still awaits the notification; it must take the shared phase.
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let store_a = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store A")
            .shared_across_replicas(true);
        let store_b = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store B")
            .shared_across_replicas(true);

        let snapshot = store_a.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let session_id = snapshot.session_id.clone();
        assert!(matches!(
            store_a.load_session(Some(&session_id), true),
            Err(SessionAccessError::NotInitialized)
        ));

        store_b
            .transition_session_to_operational(&session_id)
            .expect("notifications/initialized on B");

        let on_a = store_a
            .load_session(Some(&session_id), true)
            .expect("A sees the session operational");
        assert_eq!(on_a.phase, SessionPhase::Operational);
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
        assert!(store_b.terminate_session(&session_id).is_some());

        // A fresh replica C (reads back from the shared KV on a miss) must
        // not find it, proving the KV copy is gone.
        let store_c = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store C");
        assert!(matches!(
            store_c.load_session(Some(&session_id), false),
            Err(SessionAccessError::UnknownSession)
        ));
    }

    fn short_idle_config() -> SessionStoreConfig {
        SessionStoreConfig {
            session_idle_timeout_ms: 2_000,
            ..SessionStoreConfig::default()
        }
    }

    fn owned_session(store: &KvBackedSessionStore, owner: Option<&str>) -> String {
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        store.bind_session_owner(&id, owner);
        id
    }

    /// `max_sessions_per_tenant` counts the sessions of every replica that
    /// shares the store, and a session that ends frees its slot.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tenant_cap_counts_the_fleet() {
        let (_kv, a, b) = shared_pair(SessionStoreConfig::default()).await;
        let first = owned_session(&a, Some("alice"));
        let second = owned_session(&b, Some("alice"));
        assert_eq!(a.claim_tenant_slot(&first, 2), Some(true));
        assert_eq!(b.claim_tenant_slot(&second, 2), Some(true));

        let third = owned_session(&b, Some("alice"));
        assert_eq!(
            b.claim_tenant_slot(&third, 2),
            Some(false),
            "alice holds 2 across A and B"
        );
        let bobs = owned_session(&b, Some("bob"));
        assert_eq!(
            b.claim_tenant_slot(&bobs, 2),
            Some(true),
            "tenants count apart"
        );

        // B ends a session A created: its slot goes with its row.
        assert!(b.terminate_session(&first).is_some());
        let fourth = owned_session(&a, Some("alice"));
        assert_eq!(a.claim_tenant_slot(&fourth, 2), Some(true));

        let anonymous = owned_session(&a, None);
        assert_eq!(a.claim_tenant_slot(&anonymous, 1), Some(true));
        let anonymous_too = owned_session(&b, None);
        assert_eq!(b.claim_tenant_slot(&anonymous_too, 1), Some(false));
    }

    /// Claims racing on several replicas never hold more than the cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn racing_tenant_claims_never_exceed_the_cap() {
        let (kv, a, b) = shared_pair(SessionStoreConfig::default()).await;
        let stores = std::sync::Arc::new([a, b]);
        let mut claims = Vec::new();
        for n in 0..40 {
            let stores = std::sync::Arc::clone(&stores);
            claims.push(tokio::task::spawn_blocking(move || {
                let store = &stores[n % 2];
                let id = owned_session(store, Some("carol"));
                store.claim_tenant_slot(&id, 5) == Some(true)
            }));
        }
        let mut admitted = 0;
        for claim in claims {
            if claim.await.unwrap() {
                admitted += 1;
            }
        }
        let slots = futures::executor::block_on(
            kv.list_prefix(&KvBackedSessionStore::tenant_slot_prefix("carol"), 100),
        )
        .unwrap()
        .len();
        assert!(admitted <= 5, "admitted {admitted} over the cap of 5");
        assert_eq!(slots, admitted, "one slot per admitted session");
    }

    /// A slot the store lost comes back with the next write of its row.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tenant_slot_is_written_with_its_row() {
        let (kv, a, _b) = shared_pair(SessionStoreConfig::default()).await;
        let id = owned_session(&a, Some("dave"));
        assert_eq!(a.claim_tenant_slot(&id, 3), Some(true));
        let slot = format!("{}{id}", KvBackedSessionStore::tenant_slot_prefix("dave"));
        assert!(futures::executor::block_on(kv.delete(&slot)).unwrap());

        a.transition_session_to_operational(&id).unwrap();
        let entry = futures::executor::block_on(kv.get(&slot))
            .unwrap()
            .expect("written again");
        assert!(entry.expires_at.is_some(), "with the row's TTL");
    }

    /// A store that is not shared keeps no fleet count.
    #[test]
    fn a_store_of_its_own_counts_nothing_for_the_fleet() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = owned_session(&store, Some("erin"));
        assert_eq!(store.claim_tenant_slot(&id, 1), None);
    }

    /// The watch engine's sweeper asks whether a subscriber's session is in
    /// use anywhere: a session another replica's row keeps in use is, one
    /// ended or idle everywhere is not, and a store that holds only its own
    /// replica's sessions cannot say.
    #[tokio::test(flavor = "multi_thread")]
    async fn session_alive_answers_for_the_fleet() {
        let (_kv, a, b) = shared_pair(short_idle_config()).await;
        let id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        assert_eq!(a.session_alive(&id), Some(true));
        assert_eq!(b.session_alive(&id), Some(true), "B reads A's row");
        assert_eq!(b.session_alive("never-created"), Some(false));

        backdate_session(&a, &id, chrono::Duration::seconds(5));
        assert_eq!(
            a.session_alive(&id),
            Some(true),
            "an idle local copy defers to the row"
        );

        assert!(a.terminate_session(&id).is_some());
        assert_eq!(a.session_alive(&id), Some(false));
        assert_eq!(b.session_alive(&id), Some(false));

        let idle = KvBackedSessionStore::new_in_memory(SessionStoreConfig {
            session_idle_timeout_ms: 1,
            ..SessionStoreConfig::default()
        });
        let id = idle
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            idle.session_alive(&id),
            Some(false),
            "idle in every copy is ended"
        );

        let own =
            KvBackedSessionStore::new_in_memory(SessionStoreConfig::default()).fleet_visible(false);
        let id = own
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        assert_eq!(own.session_alive(&id), None);
    }

    async fn shared_pair(
        config: SessionStoreConfig,
    ) -> (
        std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        KvBackedSessionStore,
        KvBackedSessionStore,
    ) {
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let a = KvBackedSessionStore::new(config, shared_kv.clone())
            .await
            .expect("store A")
            .shared_across_replicas(true);
        let b = KvBackedSessionStore::new(config, shared_kv.clone())
            .await
            .expect("store B")
            .shared_across_replicas(true);
        (shared_kv, a, b)
    }

    fn shared_row(
        kv: &std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        session_id: &str,
    ) -> Option<(StoredSession, Option<std::time::SystemTime>)> {
        let entry =
            futures::executor::block_on(kv.get(&format!("session:{session_id}"))).unwrap()?;
        Some((
            serde_json::from_slice(&entry.bytes).unwrap(),
            entry.expires_at,
        ))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_in_use_on_one_replica_does_not_expire_on_another() {
        let (_kv, a, b) = shared_pair(short_idle_config()).await;
        let (evicted_tx, mut evicted_rx) = tokio::sync::mpsc::unbounded_channel();
        b.set_end_notifier(evicted_tx);
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true)
            .expect("B adopts the session");

        // A serves the session for longer than the idle timeout; B's own
        // copy goes idle meanwhile.
        let until = std::time::Instant::now() + std::time::Duration::from_millis(2_600);
        while std::time::Instant::now() < until {
            a.load_session(Some(&session_id), true).expect("live on A");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        let on_b = b
            .load_session(Some(&session_id), true)
            .expect("B takes the shared row instead of expiring a session in use");
        assert_eq!(on_b.session_id, session_id);
        assert!(
            evicted_rx.try_recv().is_err(),
            "no cleanup cascade for a session another replica serves"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_idle_everywhere_expires_and_its_row_goes() {
        let (kv, a, b) = shared_pair(short_idle_config()).await;
        let (evicted_tx, mut evicted_rx) = tokio::sync::mpsc::unbounded_channel();
        b.set_end_notifier(evicted_tx);
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true).unwrap();
        // The idle timeout, and the refresh interval a replica in use may
        // hold its touch back for.
        tokio::time::sleep(std::time::Duration::from_millis(3_300)).await;

        assert!(matches!(
            b.load_session(Some(&session_id), true),
            Err(SessionAccessError::UnknownSession)
        ));
        let ended = evicted_rx.try_recv().expect("the end is told");
        assert_eq!(ended.session_id, session_id);
        assert_eq!(ended.reason, SessionEndReason::IdleExpired);
        assert!(ended.recorded, "the replica that ends it records it");
        assert!(
            shared_row(&kv, &session_id).is_none(),
            "the row goes with it"
        );
    }

    /// A row idle for the idle timeout can still be in use: the replica that
    /// serves the session writes its touch at most once per refresh
    /// interval.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_row_within_a_refresh_interval_of_idle_is_still_in_use() {
        let (_kv, a, b) = shared_pair(short_idle_config()).await;
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2_300)).await;

        assert!(
            b.load_session(Some(&session_id), true).is_ok(),
            "idle for 2.3 s of a 2 s timeout, within the 1 s refresh interval"
        );
    }

    /// A replica that misses the word of an end finds the end the replica
    /// that ended the session recorded, the first time it uses the session
    /// after the verify interval, and stops serving it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replica_that_misses_an_end_finds_it_within_the_verify_interval() {
        let (kv, a, b) = shared_pair(short_idle_config()).await;
        let (end_tx, mut end_rx) = tokio::sync::mpsc::unbounded_channel();
        b.set_end_notifier(end_tx);
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true)
            .expect("B serves the session too");
        let ended = a.terminate_session(&session_id).expect("A ends it");
        assert!(ended.recorded, "A records the end");

        // The verify interval of a 2 s idle timeout is its 1 s refresh interval.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(matches!(
            b.load_session(Some(&session_id), true),
            Err(SessionAccessError::UnknownSession)
        ));
        let told = end_rx.try_recv().expect("B tells its runtime");
        assert_eq!(told.session_id, session_id);
        assert_eq!(told.reason, SessionEndReason::Terminated);
        assert!(!told.recorded, "A recorded it");
        assert!(shared_row(&kv, &session_id).is_none());
    }

    /// A row a replica writes after the end of its session — a write that was
    /// in flight, by a replica that had not heard of the end — does not bring
    /// the session back on a replica that reads it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_row_written_after_the_end_does_not_bring_the_session_back() {
        let (kv, a, b) = shared_pair(SessionStoreConfig::default()).await;
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true).unwrap();
        let in_flight = b.sessions.get(&session_id).unwrap().clone();
        assert!(a.terminate_session(&session_id).is_some());

        assert!(b.persist_session(&in_flight));
        assert!(
            shared_row(&kv, &session_id).is_some(),
            "B still holds its copy, so its row stays"
        );
        let c = KvBackedSessionStore::new(SessionStoreConfig::default(), kv.clone())
            .await
            .expect("store C")
            .shared_across_replicas(true);
        assert!(matches!(
            c.load_session(Some(&session_id), false),
            Err(SessionAccessError::UnknownSession)
        ));
        assert_eq!(c.session_alive(&session_id), Some(false));
    }

    /// A write that lands after the session ended on the same replica takes
    /// its rows with it, in a store of its own or a shared one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_that_lands_after_the_end_here_takes_its_rows_with_it() {
        let (_kv, shared, _b) = shared_pair(SessionStoreConfig::default()).await;
        let own = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        for store in [&shared, &own] {
            let session_id = owned_session(store, Some("frank"));
            let slot = format!(
                "{}{session_id}",
                KvBackedSessionStore::tenant_slot_prefix("frank")
            );
            let in_flight = {
                let mut copy = store.sessions.get_mut(&session_id).unwrap();
                copy.tenant_slot = true;
                copy.clone()
            };
            assert!(store.terminate_session(&session_id).is_some());

            assert!(store.persist_session(&in_flight));
            let row = futures::executor::block_on(
                store
                    .state
                    .get(&KvBackedSessionStore::session_key(&session_id)),
            )
            .unwrap();
            assert!(row.is_none(), "the late row goes");
            let slot = futures::executor::block_on(store.state.get(&slot)).unwrap();
            assert!(slot.is_none(), "and its tenant slot");
        }
    }

    /// Of the replicas that end a session at once, one records the end, so
    /// the cleanup they share runs once.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_end_is_recorded_once_for_the_fleet() {
        let (_kv, a, b) = shared_pair(short_idle_config()).await;
        let (a_tx, mut a_rx) = tokio::sync::mpsc::unbounded_channel();
        a.set_end_notifier(a_tx);
        let (b_tx, mut b_rx) = tokio::sync::mpsc::unbounded_channel();
        b.set_end_notifier(b_tx);
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        a.transition_session_to_operational(&session_id).unwrap();
        b.load_session(Some(&session_id), true).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(3_300)).await;

        a.evict_if_expired(&session_id);
        b.evict_if_expired(&session_id);
        let ends = [
            a_rx.try_recv().expect("A ends its copy"),
            b_rx.try_recv().expect("B ends its copy"),
        ];
        assert_eq!(ends.iter().filter(|end| end.recorded).count(), 1);
    }

    /// The end of a session does not end a later session under its id, on
    /// this replica or on one that reads the later one back.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_end_of_a_session_does_not_end_a_later_one_under_its_id() {
        let (_kv, a, b) = shared_pair(SessionStoreConfig::default()).await;
        let id = "mcpg-m-same";
        let first = a.create_session_with_id(id, SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert!(a.terminate_session(id).is_some());
        let second = a.create_session_with_id(id, SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        assert_ne!(first.created_at, second.created_at);

        assert!(
            b.load_session(Some(id), false).is_ok(),
            "the later session reads back"
        );
        assert!(
            b.drop_ended_session(id, first.created_at).is_none(),
            "the word of the earlier end leaves it"
        );
        assert!(b.contains_active_session(id));
        assert_eq!(b.session_alive(id), Some(true));
    }

    /// Every stream of a session ends with it, and the last stream to go
    /// leaves nothing behind.
    #[tokio::test]
    async fn the_streams_of_a_session_end_with_it() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        store.transition_session_to_operational(&id).unwrap();
        drop(store.session_lifetime(&id).expect("a copy is held"));
        assert!(
            store.lifetimes.is_empty(),
            "a stream that goes leaves nothing"
        );

        let first = store.session_lifetime(&id).unwrap().ended();
        let second = store.session_lifetime(&id).unwrap().ended();
        assert_eq!(store.lifetimes.get(&id).map(|l| l.streams), Some(2));
        assert!(store.terminate_session(&id).is_some());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            first.await;
            second.await;
        })
        .await
        .expect("both streams end");
        assert!(store.lifetimes.is_empty());
        assert!(
            store.session_lifetime(&id).is_none(),
            "an ended session has no streams to hold"
        );
    }

    fn operational_session(store: &KvBackedSessionStore) -> String {
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        store.transition_session_to_operational(&id).unwrap();
        id
    }

    fn resume(store: &KvBackedSessionStore, id: &str, event: &SseEventRecord) -> StreamAccessError {
        store
            .open_sse_stream(
                Some(id),
                Some(&ResumeCursor {
                    last_event_id: event.event_id.clone(),
                }),
            )
            .err()
            .unwrap_or(StreamAccessError::UnknownSession)
    }

    /// Every request opens a stream; a session keeps the replay of its most
    /// recent ones, so its row stays small however many requests it serves.
    #[test]
    fn a_session_keeps_the_replay_of_its_recent_streams_only() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = operational_session(&store);
        let mut answers = Vec::new();
        for _ in 0..200 {
            answers.push(
                store
                    .stream_protocol_response(&id, &ProtocolResponse::NotificationAccepted)
                    .unwrap(),
            );
        }
        let kept = store.sessions.get(&id).unwrap().streams.len();
        assert_eq!(kept, RETAINED_STREAMS, "streams kept after 200 requests");

        let last = answers.last().unwrap().last().unwrap();
        assert!(
            store
                .open_sse_stream(
                    Some(&id),
                    Some(&ResumeCursor {
                        last_event_id: answers[199][0].event_id.clone(),
                    }),
                )
                .unwrap()
                .contains(last),
            "the latest stream resumes"
        );
        assert_eq!(
            resume(&store, &id, &answers[0][0]),
            StreamAccessError::ExpiredCursor,
            "a retired stream is an expired cursor, not an invalid one"
        );
        assert_eq!(
            resume(
                &store,
                &id,
                &SseEventRecord {
                    event_id: "stream-9999:0".to_owned(),
                    data: String::new(),
                    retry_ms: None,
                }
            ),
            StreamAccessError::InvalidCursor
        );
    }

    /// A response stream holds its whole result: the replay drops the
    /// oldest streams once their events pass the byte budget.
    #[test]
    fn large_results_keep_the_replay_under_its_byte_budget() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = operational_session(&store);
        let result = serde_json::json!({ "text": "x".repeat(100 * 1024) });
        for n in 0..10 {
            let answer = ProtocolResponse::JsonRpcSuccess(crate::protocol::JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: serde_json::json!(n),
                result: result.clone(),
            });
            store.stream_protocol_response(&id, &answer).unwrap();
        }
        let session = store.sessions.get(&id).unwrap();
        let bytes: usize = session
            .streams
            .values()
            .map(StoredStream::replay_bytes)
            .sum();
        assert!(
            bytes <= RETAINED_REPLAY_BYTES,
            "{bytes} bytes of replay in {} streams",
            session.streams.len()
        );
        assert!(
            session
                .streams
                .contains_key(session.active_stream_id.as_deref().unwrap()),
            "the active stream stays"
        );
    }

    /// The word of an end another replica recorded ends this replica's
    /// streams of the session, though the copy has left its working set.
    #[test]
    fn the_word_of_an_end_ends_the_streams_here() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        store.transition_session_to_operational(&id).unwrap();
        let created_at = store.sessions.get(&id).unwrap().created_at;
        let ended = store.session_lifetime(&id).unwrap().ended();
        store.sessions.remove(&id);

        assert!(store.drop_ended_session(&id, created_at).is_none());
        assert_eq!(futures::FutureExt::now_or_never(ended), Some(()));
    }

    /// A shared store that does not answer: an idle copy stays rather than
    /// end a session another replica may be serving.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_copy_stays_while_the_store_does_not_answer() {
        let kv = std::sync::Arc::new(UnansweringKv::default());
        let store = KvBackedSessionStore::new(
            SessionStoreConfig::default(),
            kv.clone() as std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
        )
        .await
        .unwrap()
        .shared_across_replicas(true);
        let id = store
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        backdate_session(&store, &id, chrono::Duration::hours(1));
        let idle = store.sessions.get(&id).unwrap().clone();
        assert!(store.persist_session(&idle), "the row is idle too");

        kv.down.store(true, std::sync::atomic::Ordering::SeqCst);
        store.evict_if_expired(&id);
        store
            .last_pruned
            .store(0, std::sync::atomic::Ordering::SeqCst);
        store.maybe_sweep();
        assert!(store.contains_active_session(&id));

        kv.down.store(false, std::sync::atomic::Ordering::SeqCst);
        store.evict_if_expired(&id);
        assert!(!store.contains_active_session(&id), "idle everywhere");
    }

    /// A store whose reads fail while `down`.
    #[derive(Debug, Default)]
    struct UnansweringKv {
        inner: crate::builtins::cluster_primitives::MemoryKv,
        down: std::sync::atomic::AtomicBool,
    }

    impl UnansweringKv {
        fn answer(&self) -> Result<(), mcpg_cluster_api::ClusterError> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(mcpg_cluster_api::ClusterError::BackendUnavailable {
                    reason: "down".to_owned(),
                });
            }
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl mcpg_cluster_api::KeyValueStore for UnansweringKv {
        async fn get(
            &self,
            key: &str,
        ) -> Result<Option<mcpg_cluster_api::Entry>, mcpg_cluster_api::ClusterError> {
            self.answer()?;
            self.inner.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            value: bytes::Bytes,
            ttl: Option<std::time::Duration>,
        ) -> Result<(), mcpg_cluster_api::ClusterError> {
            self.inner.put(key, value, ttl).await
        }
        async fn put_if_absent(
            &self,
            key: &str,
            value: bytes::Bytes,
            ttl: Option<std::time::Duration>,
        ) -> Result<bool, mcpg_cluster_api::ClusterError> {
            self.inner.put_if_absent(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<bool, mcpg_cluster_api::ClusterError> {
            self.inner.delete(key).await
        }
        async fn list_page(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> Result<mcpg_cluster_api::KvPage, mcpg_cluster_api::ClusterError> {
            self.inner.list_page(prefix, cursor, limit).await
        }
        async fn expire(
            &self,
            key: &str,
            ttl: Option<std::time::Duration>,
        ) -> Result<bool, mcpg_cluster_api::ClusterError> {
            self.inner.expire(key, ttl).await
        }
        async fn incr(
            &self,
            key: &str,
            delta: i64,
            ttl: Option<std::time::Duration>,
        ) -> Result<i64, mcpg_cluster_api::ClusterError> {
            self.inner.incr(key, delta, ttl).await
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_read_refreshes_the_shared_row_at_most_once_per_interval() {
        let (kv, a, _b) = shared_pair(short_idle_config()).await;
        let session_id = a
            .create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params())
            .session_id;
        let (created, expires_at) = shared_row(&kv, &session_id).expect("row written");
        let ttl = expires_at
            .expect("the row has a TTL")
            .duration_since(std::time::SystemTime::now())
            .unwrap();
        assert!(
            ttl > std::time::Duration::from_millis(3_500),
            "idle timeout plus two refresh intervals, got {ttl:?}"
        );

        a.load_session(Some(&session_id), false).unwrap();
        let (unchanged, _) = shared_row(&kv, &session_id).unwrap();
        assert_eq!(
            unchanged.last_seen_at, created.last_seen_at,
            "a read within the refresh interval does not write"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        a.load_session(Some(&session_id), false).unwrap();
        let (refreshed, _) = shared_row(&kv, &session_id).unwrap();
        assert!(
            refreshed.last_seen_at > created.last_seen_at,
            "a read after the refresh interval writes the row"
        );
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
            assert!(store.terminate_session(&snapshot.session_id).is_some());
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
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EndedSession>();
        store.set_end_notifier(tx);

        let snap = store.create_session(SUPPORTED_PROTOCOL_VERSION, &test_init_params());
        let sid = snap.session_id.clone();
        assert!(store.contains_active_session(&sid));

        std::thread::sleep(std::time::Duration::from_millis(5));
        store.evict_if_expired(&sid); // lazy per-access idle expiry
        assert!(
            !store.contains_active_session(&sid),
            "the idle session must be evicted"
        );
        let ended = rx
            .try_recv()
            .expect("the evicted id must be forwarded to the runtime cascade");
        assert_eq!(ended.session_id, sid);
        assert!(ended.recorded, "a store of its own records every end");
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
            tenant_slot: false,
            last_seen_at: now,
            created_at: now,
            written_at_ms: 0,
            verified_at_ms: 0,
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
