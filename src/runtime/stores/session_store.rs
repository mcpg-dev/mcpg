//! The gateway's internal session rows. A row ties together what outlives
//! one request of a caller: its tasks, a suspended MRTR pipeline, its
//! `subscriptions/listen` streams and its delivery bus key. Rows are minted
//! by the runtime (`GatewayRuntime::ensure_session`), never named by a
//! client, and end when an operator terminates them or no replica uses them
//! for the idle timeout.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Point-in-time snapshot of a session's state, used for read-only queries
/// without holding a lock on the session store.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    /// Trust-qualified principal key of the session creator (`None` =
    /// anonymous). The owner checks on listen streams, tasks and resumes
    /// compare the caller against it.
    pub owner_principal: Option<String>,
}

/// Tuning knobs for the session store: idle timeout and capacity limits.
/// Every backend (in-memory, file, NATS KV, Redis) shares this config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStoreConfig {
    pub session_idle_timeout_ms: u64,
    /// Maximum number of concurrent sessions. 0 = unlimited.
    pub max_sessions: usize,
    /// Sessions one principal may hold at once. 0 = unlimited. The stricter
    /// of this and `max_sessions` wins.
    pub max_sessions_per_tenant: usize,
}

impl Default for SessionStoreConfig {
    fn default() -> Self {
        Self {
            session_idle_timeout_ms: 900_000,
            max_sessions: 10_000,
            max_sessions_per_tenant: 0,
        }
    }
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// An operator ended the session.
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
    /// Persist a new session under a fresh random id. A store at
    /// `max_sessions` answers with an empty-id snapshot and keeps nothing.
    fn create_session(&self) -> SessionSnapshot;
    /// Create a session under a caller-supplied id, returning the existing
    /// snapshot unchanged if one already lives at `session_id` (idempotent).
    ///
    /// Every replica derives the same id for a principal, so the row —
    /// persisted to cluster KV — is shared. The default impl ignores the id
    /// and mints a random one (in-process stores have no cross-replica
    /// notion); cluster-KV-backed stores override.
    fn create_session_with_id(&self, session_id: &str) -> SessionSnapshot {
        let _ = session_id;
        self.create_session()
    }
    /// Record the trust-qualified principal key that owns `session_id`.
    /// Default no-op for in-process / test stores that don't surface owner
    /// binding.
    fn bind_session_owner(&self, session_id: &str, owner_principal: Option<&str>) {
        let _ = (session_id, owner_principal);
    }
    /// The live session under `session_id`, which the read keeps alive;
    /// `None` when none lives under it.
    fn load_session(&self, session_id: &str) -> Option<SessionSnapshot>;
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
    /// truly-gone session from one the runtime minted again under the same id.
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

    /// List active sessions. Returns summary snapshots.
    fn list_sessions(&self) -> Vec<SessionSnapshot> {
        vec![]
    }

    /// Count active sessions without allocating.
    fn active_session_count(&self) -> usize {
        self.list_sessions().len()
    }
}

/// A session row: who owns it and when it was last used. It holds no
/// stream or replay state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    session_id: String,
    /// Trust-qualified principal key of the session creator (trust tier +
    /// provider + issuer + subject; `None` for an anonymous creator).
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
    fn new(session_id: String) -> Self {
        let now = Utc::now();
        Self {
            session_id,
            owner_principal: None,
            tenant_slot: false,
            last_seen_at: now,
            created_at: now,
            written_at_ms: 0,
            verified_at_ms: now.timestamp_millis(),
        }
    }

    fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            session_id: self.session_id.clone(),
            created_at: self.created_at,
            owner_principal: self.owner_principal.clone(),
        }
    }

    fn touch(&mut self) {
        self.last_seen_at = Utc::now();
    }
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

/// The snapshot a store answers a refused create with: an empty id.
fn refused_snapshot() -> SessionSnapshot {
    SessionSnapshot {
        session_id: String::new(),
        created_at: Utc::now(),
        owner_principal: None,
    }
}

/// Whether the session limit is reached.
fn session_limit_reached(
    sessions: &dashmap::DashMap<String, StoredSession>,
    config: &SessionStoreConfig,
) -> bool {
    if config.max_sessions > 0 && sessions.len() >= config.max_sessions {
        tracing::warn!(
            current = sessions.len(),
            max = config.max_sessions,
            "session limit reached, rejecting new session"
        );
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// KvBackedSessionStore — single impl over the orthogonal KvState primitive
// ---------------------------------------------------------------------------

/// Session store backed by any [`mcpg_cluster_api::KeyValueStore`] impl.
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
/// `mcpg_active_sessions` moves here: up when a create inserts a new copy,
/// down when this replica records an end. Summed over the fleet it is the
/// number of live rows.
pub struct KvBackedSessionStore {
    config: SessionStoreConfig,
    state: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    /// Sharded so requests on different sessions don't serialise on one lock.
    /// Expiry is lazy per-entry on access + a throttled full sweep
    /// (`maybe_sweep`), NOT an O(N) scan on every request.
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
    /// Sync constructor over an empty in-process `MemoryKv`. Useful for
    /// tests + the `cluster.kind: single_node` boot path.
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

    /// Mark the KV as shared with other replicas: an idle copy defers to the
    /// shared row, and the end of a session is recorded for the fleet.
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

    /// Insert `session`, a copy this replica just created, into the working
    /// set and count it as active.
    fn insert_created(&self, session: StoredSession) {
        self.sessions.insert(session.session_id.clone(), session);
        metrics::gauge!("mcpg_active_sessions").increment(1.0);
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
        if recorded {
            metrics::gauge!("mcpg_active_sessions").decrement(1.0);
        }
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
    /// so a concurrent `touch()` can't be clobbered). O(1). A copy that is
    /// idle here while another replica keeps the session in use takes the
    /// shared row instead; one the store cannot tell about stays.
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
    /// absent and this wins; the create-once guard means two replicas that
    /// ever derive the same id cannot clobber a live row. Returns whether
    /// the row was written by this call.
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
    /// No KV round-trip when the session is already local (the
    /// same-replica happy path) beyond the throttled end check of
    /// [`Self::verify_copy`]. The `sessions` lock is held only for the
    /// membership check and the final insert, never across the (blocking)
    /// KV read.
    fn ensure_hydrated(&self, session_id: &str) {
        if self.sessions.contains_key(session_id) {
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
}

impl SessionStore for KvBackedSessionStore {
    fn create_session(&self) -> SessionSnapshot {
        let mut session = StoredSession::new(uuid::Uuid::new_v4().to_string());
        let snapshot = session.snapshot();
        self.maybe_sweep();
        if session_limit_reached(&self.sessions, &self.config) {
            return refused_snapshot();
        }
        // Create-once: a fresh random-UUID session must not clobber a live
        // row of the same id.
        if self.persist_session_create_once(&session) {
            session.written_at_ms = session.created_at.timestamp_millis();
        }
        self.insert_created(session);
        snapshot
    }

    fn create_session_with_id(&self, session_id: &str) -> SessionSnapshot {
        // Idempotent: if the row already exists (this replica, or another
        // via the KV read-back hydration), return it unchanged so
        // concurrent cross-replica creates of the same derived id
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
        self.maybe_sweep();
        if session_limit_reached(&self.sessions, &self.config) {
            return refused_snapshot();
        }
        // The copy goes in before the row is written: a row whose copy is gone
        // belongs to an ended session. A concurrent create under the same id
        // that went in first wins.
        let (snapshot, stored) = {
            use dashmap::mapref::entry::Entry;
            match self.sessions.entry(session_id.to_owned()) {
                Entry::Occupied(copy) => (copy.get().snapshot(), copy.get().clone()),
                Entry::Vacant(slot) => {
                    let copy = slot.insert(StoredSession::new(session_id.to_owned()));
                    metrics::gauge!("mcpg_active_sessions").increment(1.0);
                    (copy.snapshot(), copy.clone())
                }
            }
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

    fn load_session(&self, session_id: &str) -> Option<SessionSnapshot> {
        self.ensure_hydrated(session_id);
        self.evict_if_expired(session_id);
        self.maybe_sweep();
        let mut session = self.sessions.get_mut(session_id)?;
        session.touch();
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
        Some(snapshot)
    }

    fn terminate_session(&self, session_id: &str) -> Option<EndedSession> {
        // Hydrate first so a terminate that lands on a replica which never
        // saw the session still removes the shared KV copy — otherwise the
        // session would resurrect via read-back elsewhere.
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

    fn list_sessions(&self) -> Vec<SessionSnapshot> {
        self.sessions.iter().map(|e| e.value().snapshot()).collect()
    }

    fn active_session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// A recorder that keeps the net movement of `mcpg_active_sessions` on the
/// thread it is installed on, for tests that check the gauge balances.
#[cfg(test)]
pub(crate) mod active_sessions_probe {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    #[derive(Default)]
    struct Net(AtomicI64);

    impl metrics::GaugeFn for Net {
        fn increment(&self, value: f64) {
            self.0.fetch_add(value as i64, Ordering::SeqCst);
        }
        fn decrement(&self, value: f64) {
            self.0.fetch_sub(value as i64, Ordering::SeqCst);
        }
        fn set(&self, value: f64) {
            self.0.store(value as i64, Ordering::SeqCst);
        }
    }

    #[derive(Default, Clone)]
    pub(crate) struct ActiveSessions(Arc<Net>);

    impl ActiveSessions {
        /// Run `f` with this recorder installed on the current thread.
        pub(crate) fn watch<T>(&self, f: impl FnOnce() -> T) -> T {
            metrics::with_local_recorder(self, f)
        }

        /// Increments minus decrements seen so far.
        pub(crate) fn net(&self) -> i64 {
            self.0.0.load(Ordering::SeqCst)
        }
    }

    impl metrics::Recorder for ActiveSessions {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            metrics::Counter::noop()
        }
        fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            if key.name() == "mcpg_active_sessions" {
                metrics::Gauge::from_arc(Arc::clone(&self.0))
            } else {
                metrics::Gauge::noop()
            }
        }
        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_path_buf();
        (dir, path)
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
        let id = store.create_session().session_id;
        // Just past the 15-minute window: 900_001 ms >= the 900_000 ms idle
        // timeout, so the session must be pruned on the next access.
        backdate_session(&store, &id, chrono::Duration::milliseconds(900_001));
        assert!(
            store.load_session(&id).is_none(),
            "expired session must be pruned"
        );
    }

    #[test]
    fn fresh_session_survives_realistic_ms_timeout() {
        let store = ms_timeout_store();
        let id = store.create_session().session_id;
        assert!(store.load_session(&id).is_some());
    }

    #[test]
    fn session_just_under_ms_timeout_survives() {
        let store = ms_timeout_store();
        let id = store.create_session().session_id;
        backdate_session(&store, &id, chrono::Duration::milliseconds(899_000));
        assert!(store.load_session(&id).is_some());
    }

    #[test]
    fn bind_session_owner_round_trips_via_snapshot() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store.create_session().session_id;
        // A freshly created session has no owner until bound.
        assert!(store.load_session(&id).unwrap().owner_principal.is_none());
        store.bind_session_owner(&id, Some("alice"));
        assert_eq!(
            store.load_session(&id).unwrap().owner_principal.as_deref(),
            Some("alice")
        );
    }

    /// A row carries the session's owner and times and nothing else: no
    /// stream, replay or log-level state is ever written into it.
    #[test]
    fn a_row_holds_no_stream_or_replay_state() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store.create_session().session_id;
        store.bind_session_owner(&id, Some("alice"));
        let entry =
            futures::executor::block_on(store.state.get(&KvBackedSessionStore::session_key(&id)))
                .unwrap()
                .expect("row written");
        let row: serde_json::Value = serde_json::from_slice(&entry.bytes).unwrap();
        let mut keys: Vec<&str> = row
            .as_object()
            .expect("a row is an object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "created_at",
                "last_seen_at",
                "owner_principal",
                "session_id"
            ]
        );
    }

    /// A row a replica of an earlier build wrote, with stream and handshake
    /// fields beside the owner, still reads back.
    #[test]
    fn a_row_with_fields_this_build_does_not_keep_still_reads() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let now = Utc::now().to_rfc3339();
        let row = serde_json::json!({
            "session_id": "s-old",
            "protocol_version": "x",
            "phase": "Operational",
            "streams": {},
            "owner_principal": "verified::idp::iss::alice",
            "last_seen_at": now,
            "created_at": now,
        });
        futures::executor::block_on(store.state.put(
            &KvBackedSessionStore::session_key("s-old"),
            bytes::Bytes::from(serde_json::to_vec(&row).unwrap()),
            None,
        ))
        .unwrap();
        let snapshot = store.load_session("s-old").expect("reads back");
        assert_eq!(
            snapshot.owner_principal.as_deref(),
            Some("verified::idp::iss::alice")
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
            session_id = store.create_session().session_id;
            store.bind_session_owner(&session_id, Some("alice"));
        }

        {
            let store = KvBackedSessionStore::new_with_file(
                SessionStoreConfig::default(),
                data_dir.clone(),
            )
            .await
            .expect("store created");
            let snapshot = store.load_session(&session_id).expect("session recovered");
            assert_eq!(snapshot.session_id, session_id);
            assert_eq!(snapshot.owner_principal.as_deref(), Some("alice"));
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

        let session_id = store_a.create_session().session_id;
        store_a.bind_session_owner(&session_id, Some("alice"));

        // B never saw this session locally; the read path must hydrate it
        // from the shared KV instead of finding nothing.
        let recovered = store_b
            .load_session(&session_id)
            .expect("B resolves the session via KV read-back");
        assert_eq!(recovered.session_id, session_id);
        assert_eq!(recovered.owner_principal.as_deref(), Some("alice"));
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

        let session_id = store_a.create_session().session_id;

        // B terminates a session it never saw locally → must clear KV.
        assert!(store_b.terminate_session(&session_id).is_some());

        // A fresh replica C (reads back from the shared KV on a miss) must
        // not find it, proving the KV copy is gone.
        let store_c = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store C");
        assert!(store_c.load_session(&session_id).is_none());
    }

    fn short_idle_config() -> SessionStoreConfig {
        SessionStoreConfig {
            session_idle_timeout_ms: 2_000,
            ..SessionStoreConfig::default()
        }
    }

    fn owned_session(store: &KvBackedSessionStore, owner: Option<&str>) -> String {
        let id = store.create_session().session_id;
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

        a.bind_session_owner(&id, Some("dave"));
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
        let id = a.create_session().session_id;
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
        let id = idle.create_session().session_id;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(
            idle.session_alive(&id),
            Some(false),
            "idle in every copy is ended"
        );

        let own =
            KvBackedSessionStore::new_in_memory(SessionStoreConfig::default()).fleet_visible(false);
        let id = own.create_session().session_id;
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id).expect("B adopts the session");

        // A serves the session for longer than the idle timeout; B's own
        // copy goes idle meanwhile.
        let until = std::time::Instant::now() + std::time::Duration::from_millis(2_600);
        while std::time::Instant::now() < until {
            a.load_session(&session_id).expect("live on A");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        let on_b = b
            .load_session(&session_id)
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id).unwrap();
        // The idle timeout, and the refresh interval a replica in use may
        // hold its touch back for.
        tokio::time::sleep(std::time::Duration::from_millis(3_300)).await;

        assert!(b.load_session(&session_id).is_none());
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2_300)).await;

        assert!(
            b.load_session(&session_id).is_some(),
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id)
            .expect("B serves the session too");
        let ended = a.terminate_session(&session_id).expect("A ends it");
        assert!(ended.recorded, "A records the end");

        // The verify interval of a 2 s idle timeout is its 1 s refresh interval.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(b.load_session(&session_id).is_none());
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id).unwrap();
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
        assert!(c.load_session(&session_id).is_none());
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
        let session_id = a.create_session().session_id;
        b.load_session(&session_id).unwrap();
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
        let first = a.create_session_with_id(id);
        assert!(a.terminate_session(id).is_some());
        let second = a.create_session_with_id(id);
        assert_ne!(first.created_at, second.created_at);

        assert!(b.load_session(id).is_some(), "the later session reads back");
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
        let id = store.create_session().session_id;
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

    /// The word of an end another replica recorded ends this replica's
    /// streams of the session, though the copy has left its working set.
    #[test]
    fn the_word_of_an_end_ends_the_streams_here() {
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let id = store.create_session().session_id;
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
        let id = store.create_session().session_id;
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
        let session_id = a.create_session().session_id;
        let (created, expires_at) = shared_row(&kv, &session_id).expect("row written");
        let ttl = expires_at
            .expect("the row has a TTL")
            .duration_since(std::time::SystemTime::now())
            .unwrap();
        assert!(
            ttl > std::time::Duration::from_millis(3_500),
            "idle timeout plus two refresh intervals, got {ttl:?}"
        );

        a.load_session(&session_id).unwrap();
        let (unchanged, _) = shared_row(&kv, &session_id).unwrap();
        assert_eq!(
            unchanged.last_seen_at, created.last_seen_at,
            "a read within the refresh interval does not write"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        a.load_session(&session_id).unwrap();
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
            let snapshot = store.create_session();
            assert!(store.terminate_session(&snapshot.session_id).is_some());
            snapshot.session_id
        };

        let store =
            KvBackedSessionStore::new_with_file(SessionStoreConfig::default(), data_dir.clone())
                .await
                .expect("store created");
        assert!(store.load_session(&session_id).is_none());
    }

    /// `mcpg_active_sessions` goes up once per row a create inserts and down
    /// once per end this replica records: an idempotent create, a read-back
    /// and the end another replica records move it not at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_active_sessions_gauge_balances() {
        let (_kv, a, b) = shared_pair(short_idle_config()).await;
        let probe = active_sessions_probe::ActiveSessions::default();
        probe.watch(|| {
            let first = a.create_session().session_id;
            let derived = a.create_session_with_id("mcpg-m-gauge").session_id;
            assert_eq!(a.create_session_with_id("mcpg-m-gauge").session_id, derived);
            assert_eq!(probe.net(), 2, "two rows, one of them created twice");

            b.load_session(&first).expect("B reads A's row back");
            assert_eq!(probe.net(), 2, "a read-back creates nothing");

            assert!(a.terminate_session(&first).unwrap().recorded);
            assert!(!b.terminate_session(&first).is_some_and(|end| end.recorded));
            assert!(a.terminate_session(&derived).unwrap().recorded);
            assert_eq!(probe.net(), 0, "every row created is ended once");
        });
    }
}

#[cfg(test)]
mod session_limit_store_tests {
    use super::*;

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

        let snap1 = store.create_session();
        assert!(!snap1.session_id.is_empty(), "first session should succeed");

        let snap2 = store.create_session();
        assert!(
            !snap2.session_id.is_empty(),
            "second session should succeed"
        );

        let snap3 = store.create_session();
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

        let snap1 = store.create_session();
        assert!(!snap1.session_id.is_empty(), "first session should succeed");

        let snap2 = store.create_session();
        assert!(
            snap2.session_id.is_empty(),
            "second session should be rejected"
        );
        assert!(
            store
                .create_session_with_id("mcpg-m-over")
                .session_id
                .is_empty(),
            "a derived id is refused at the limit too"
        );
    }

    #[test]
    fn create_session_with_id_uses_the_supplied_id_and_is_idempotent() {
        // Every replica derives the same id for a principal; the store must
        // honour it and converge on one session for repeat calls
        // (concurrent cross-replica creates of the same id).
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig::default());
        let sid = "mcpg-m-deadbeef";
        let snap1 = store.create_session_with_id(sid);
        assert_eq!(snap1.session_id, sid, "must use the caller-supplied id");

        // A second call with the same id returns the SAME session, not a new
        // one — so two replicas racing the same derived id agree.
        let snap2 = store.create_session_with_id(sid);
        assert_eq!(snap2.session_id, sid);
        assert_eq!(
            snap1.created_at, snap2.created_at,
            "idempotent create must not mint a fresh session"
        );

        // And it is loadable by that id (the cross-replica read path).
        assert!(store.load_session(sid).is_some());
    }

    #[test]
    fn idle_eviction_forwards_the_session_id_to_the_notifier() {
        // A session nobody terminates is dropped by idle expiry; the runtime
        // cleanup cascade needs that id, so the store must forward it on the
        // eviction channel.
        let store = KvBackedSessionStore::new_in_memory(SessionStoreConfig {
            session_idle_timeout_ms: 1,
            ..SessionStoreConfig::default()
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<EndedSession>();
        store.set_end_notifier(tx);

        let sid = store.create_session().session_id;
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
    async fn create_session_is_create_once_against_shared_kv() {
        // The create persists with `put_if_absent`, so a live row already in
        // the shared KV under the same id is never clobbered by a re-create.
        let shared_kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> =
            std::sync::Arc::new(crate::builtins::cluster_primitives::MemoryKv::new());
        let store_a = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store A");

        let sid = store_a.create_session().session_id;
        store_a.bind_session_owner(&sid, Some("alice"));

        // A second replica that minted the SAME id (the pathological
        // create-once case) must not overwrite the live shared row with a
        // fresh unowned one.
        let store_b = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store B");
        let clobber = StoredSession::new(sid.clone());
        let wrote = store_b.persist_session_create_once(&clobber);
        assert!(!wrote, "create-once must lose to the live shared row");

        // The shared row still names A's owner.
        let store_c = KvBackedSessionStore::new(SessionStoreConfig::default(), shared_kv.clone())
            .await
            .expect("store C");
        let recovered = store_c.load_session(&sid).expect("C resolves");
        assert_eq!(recovered.owner_principal.as_deref(), Some("alice"));
    }
}
