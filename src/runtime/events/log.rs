//! The event log: one ordered, retained log per source key, in the
//! `event-log` store.
//!
//! Keys (the source key `sk` and every hashed part hold no cleartext,
//! because key names stay readable under state encryption):
//!
//! - `ev:head:{sk}` — the committed head: last sequence number, the writer's
//!   fence and lease expiry, the bytes retained, the last gap marker.
//! - `ev:log:{sk}:{seq:020}` — one row; TTL slightly past the retention age.
//! - `ev:eid:{sk}:{h(eventId)}` — the dedup marker of an event id.
//! - `ev:epoch:{sk}` — a random epoch; a lost log gets another, and every
//!   cursor issued under the old one becomes a gap.
//! - `ev:floor:{sk}` — the lowest retained sequence number.
//! - `ev:in:n:{sk}`, `ev:in:d:{sk}`, `ev:in:{sk}:{n:020}` — the inbox:
//!   inbound routes on any replica append rows under an atomic counter, and
//!   the writer drains them in order.
//!
//! Only the events owner writes rows, so sequence numbers are assigned by one
//! writer. A row is written with `put_if_absent` before the head moves, so a
//! second writer in a split-brain window can never overwrite one; it finds
//! the slot taken, adopts it, and yields when the head carries a newer fence.
//! Readers never read past the head and read rows with point gets. Sequence
//! numbers start at 1; head 0 is an empty log.
//!
//! A row never changes once written, so a process keeps the recent rows it
//! wrote or read, and its readers read each from the store once. An inbox
//! drain appends its rows under one hold of the log and moves the head after
//! every [`HEAD_EVERY`] rows.
//!
//! Every value carries `v: 1`. A row with a higher version is unreadable and
//! is reported as such, never guessed at.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use mcpg_cluster_api::{ClusterError, KeyValueStore, PubSub};
use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::cursor::{CursorPosition, CursorScope, LogBounds, Resume};
use super::keys::EventsKeys;
use super::occurrence::StoredOccurrence;
use crate::config::events::EventRetentionConfig;
use crate::protocol::v_2026_07_28::extensions::events::errors::ForbiddenReason;
use crate::protocol::v_2026_07_28::extensions::events::schema::{SchemaRole, is_additive_change};

/// Version of every value this module writes.
pub const FORMAT_VERSION: u32 = 1;
/// Topic of the hint sent when a log's head moves: `mcpg.events.{sk}`.
pub const HEAD_TOPIC_PREFIX: &str = "mcpg.events.";
/// Topic of the hint sent when an inbox gains a row.
pub const INBOX_TOPIC: &str = "mcpg.events.inbox";
/// Time a row outlives its retention age, so the reaper, not the store's
/// TTL, normally removes it and keeps the byte count exact.
pub const ROW_TTL_GRACE: Duration = Duration::from_secs(3_600);
/// Most rows one retention pass evicts.
pub const RETENTION_BATCH: u64 = 1_000;
/// Most rows one inbox drain reads.
pub const DRAIN_BATCH: u64 = 256;
/// How long the drainer waits for a reserved inbox slot to be written
/// before it skips the slot.
pub const INBOX_HOLE_GRACE: Duration = Duration::from_secs(30);
/// Rows a drain appends before it moves the head, so readers see them.
pub const HEAD_EVERY: usize = 32;
/// Store operations a drain or a read runs at once.
const PARALLEL_OPS: usize = 16;
/// Recent rows of one log a process keeps for its readers, and their bytes.
const CACHED_ROWS: usize = 1_024;
const CACHED_ROW_BYTES: u64 = 1024 * 1024;
/// How old the bounds one reader takes from another's read may be.
const BOUNDS_FRESH: Duration = Duration::from_secs(2);

/// The recent rows of one log, by sequence number.
#[derive(Default)]
struct RowCache {
    rows: BTreeMap<u64, Arc<LogRow>>,
    bytes: u64,
    /// The epoch the rows belong to, once a read of the bounds saw it.
    epoch: Option<u64>,
}

impl RowCache {
    /// Forget every row when `epoch` is not theirs: a lost log gets another
    /// epoch and numbers its rows from 1 again.
    fn keep_epoch(&mut self, epoch: u64) {
        if self.epoch != Some(epoch) {
            self.rows.clear();
            self.bytes = 0;
            self.epoch = Some(epoch);
        }
    }

    fn insert(&mut self, row: LogRow) {
        let bytes = row.bytes.max(1);
        if let Some(old) = self.rows.insert(row.seq, Arc::new(row)) {
            self.bytes = self.bytes.saturating_sub(old.bytes.max(1));
        }
        self.bytes = self.bytes.saturating_add(bytes);
        while self.rows.len() > CACHED_ROWS || self.bytes > CACHED_ROW_BYTES {
            let Some((_, oldest)) = self.rows.pop_first() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(oldest.bytes.max(1));
        }
    }

    /// Forget the rows below `floor`, which retention removed.
    fn drop_below(&mut self, floor: u64) {
        let kept = self.rows.split_off(&floor);
        for (_, row) in std::mem::replace(&mut self.rows, kept) {
            self.bytes = self.bytes.saturating_sub(row.bytes.max(1));
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Why a log operation failed.
#[derive(Debug)]
pub enum LogError {
    /// The store failed.
    Store(ClusterError),
    /// A value could not be encoded or decoded.
    Codec(String),
    /// Another writer holds the log under a newer fence.
    Deposed,
    /// This writer's lease has expired.
    LeaseExpired,
    /// A value was written by a newer format this build does not read.
    NewerFormat,
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "event log store: {error}"),
            Self::Codec(reason) => write!(f, "event log value: {reason}"),
            Self::Deposed => f.write_str("another events owner writes this log"),
            Self::LeaseExpired => f.write_str("the events owner lease has expired"),
            Self::NewerFormat => f.write_str("the event log was written by a newer format"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<ClusterError> for LogError {
    fn from(error: ClusterError) -> Self {
        Self::Store(error)
    }
}

/// The committed head of one log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRecord {
    pub v: u32,
    /// The last committed sequence number; 0 for an empty log.
    pub seq: u64,
    /// Fence of the lease the last writer held.
    pub fence: u64,
    /// When that lease expires, Unix milliseconds.
    pub lease_expires_at_ms: u64,
    /// Bytes of the retained rows.
    pub bytes: u64,
    /// Sequence number of the newest gap marker every reader sees; 0 when
    /// none.
    pub last_gap_seq: u64,
}

/// Why a gap marker was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    /// A source that cannot resume (re)started after a period it did not
    /// cover.
    SourceRestart,
    /// The upstream a source reads reported events it no longer has.
    UpstreamTruncated,
}

/// Why the upstream of an imported type ended the subscriptions of one set
/// of arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The upstream refuses the gateway these arguments.
    Forbidden,
    /// The upstream has no such event type.
    NotFound,
    /// The upstream refuses the arguments.
    ArgumentsRefused,
}

impl EndReason {
    /// The label of the termination it causes.
    pub fn label(self) -> &'static str {
        match self {
            Self::Forbidden => ForbiddenReason::UpstreamForbidden.as_str(),
            Self::NotFound => "upstream_not_found",
            Self::ArgumentsRefused => "upstream_refused_arguments",
        }
    }

    /// What a reader it ends is told. Names no upstream detail.
    pub fn error(self) -> crate::protocol::v_2026_07_28::extensions::events::errors::EventsError {
        use crate::protocol::v_2026_07_28::extensions::events::errors::{
            EventsError, NotFoundKind,
        };
        match self {
            Self::Forbidden => EventsError::forbidden(ForbiddenReason::UpstreamForbidden),
            Self::NotFound => EventsError::not_found(NotFoundKind::Event),
            Self::ArgumentsRefused => {
                EventsError::invalid_params("the upstream refuses these arguments")
            }
        }
    }
}

/// The readers a marker row is for: every reader, or only those of one
/// principal (`audience`) and of one set of arguments (`arguments`), each
/// named by its keyed hash.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

impl RowScope {
    /// The readers of the arguments with keyed hash `arguments`, of any
    /// principal or, with `audience`, of that one.
    pub fn of(audience: Option<String>, arguments: String) -> Self {
        Self {
            audience,
            arguments: Some(arguments),
        }
    }

    /// Whether a reader with these keyed hashes is one of them.
    pub fn includes(&self, audience: &str, arguments: &str) -> bool {
        self.audience.as_deref().is_none_or(|a| a == audience)
            && self.arguments.as_deref().is_none_or(|a| a == arguments)
    }
}

/// The content of one row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RowBody {
    /// One occurrence.
    Event(StoredOccurrence),
    /// Events may have been missed here, by the readers of `scope`.
    Gap {
        reason: GapReason,
        #[serde(default, skip_serializing_if = "is_every_reader")]
        scope: RowScope,
    },
    /// The subscriptions of the readers of `scope` end here, after the rows
    /// before it.
    Ended { reason: EndReason, scope: RowScope },
}

fn is_every_reader(scope: &RowScope) -> bool {
    *scope == RowScope::default()
}

impl RowBody {
    /// Whether a reader with these keyed hashes sees this row as a gap.
    pub fn is_gap_for(&self, audience: &str, arguments: &str) -> bool {
        matches!(self, Self::Gap { scope, .. } if scope.includes(audience, arguments))
    }

    /// Why a reader with these keyed hashes ends at this row, when it does.
    pub fn ends(&self, audience: &str, arguments: &str) -> Option<EndReason> {
        match self {
            Self::Ended { reason, scope } if scope.includes(audience, arguments) => Some(*reason),
            _ => None,
        }
    }
}

/// One stored row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogRow {
    pub v: u32,
    pub seq: u64,
    /// When the writer appended it, Unix milliseconds.
    pub appended_at_ms: u64,
    /// Encoded size, as counted against the byte budget.
    pub bytes: u64,
    #[serde(flatten)]
    pub body: RowBody,
}

/// A row as a reader sees it.
#[derive(Debug, Clone, PartialEq)]
pub enum LogEntry {
    /// A readable row.
    Row(LogRow),
    /// A row written by a newer format this build does not read.
    Unreadable { seq: u64 },
}

impl LogEntry {
    pub fn seq(&self) -> u64 {
        match self {
            Self::Row(row) => row.seq,
            Self::Unreadable { seq } => *seq,
        }
    }
}

/// An inbox row: an occurrence any replica took in, for the owner to
/// append.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InboxRow {
    pub v: u32,
    /// The sender's event id, when it has one.
    pub event_id: Option<String>,
    /// When the event happened, RFC 3339.
    pub timestamp: Option<String>,
    pub data: serde_json::Value,
    pub received_at_ms: u64,
    /// The only principal it may reach, as a keyed hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The only arguments it answers, as a keyed hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// A marker in place of an occurrence, for the readers `audience` and
    /// `arguments` name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker: Option<InboxMarker>,
}

/// A marker an inbox row carries in place of an occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InboxMarker {
    Gap { reason: GapReason },
    Ended { reason: EndReason },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InboxDrained {
    v: u32,
    n: u64,
    at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochRecord {
    v: u32,
    epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FloorRecord {
    v: u32,
    floor: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DedupMarker {
    v: u32,
    seq: u64,
}

/// What an inbox write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxOutcome {
    /// The row is durably written.
    Accepted,
    /// The inbox is full or has not been drained for too long; the sender
    /// should retry after the given time.
    Full { retry_after: Duration },
}

/// The bounds an inbox write checks.
#[derive(Debug, Clone, Copy)]
pub struct InboxLimits {
    pub ttl: Duration,
    pub max_rows: u64,
}

/// What an append did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Written at sequence number `seq`, as a row of `bytes`.
    Appended { seq: u64, bytes: u64 },
    /// The event id was appended before.
    Duplicate,
}

impl AppendOutcome {
    /// The sequence number written at, `None` for a duplicate.
    pub fn seq(&self) -> Option<u64> {
        match self {
            Self::Appended { seq, .. } => Some(*seq),
            Self::Duplicate => None,
        }
    }
}

/// What one inbox drain pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxDrain {
    /// Inbox rows taken, whatever became of them.
    pub consumed: u64,
    /// Occurrences appended; a duplicate or a dropped row counts nothing.
    pub appended: u64,
    /// The bytes of the appended rows.
    pub bytes: u64,
}

/// Where a reader starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePoint {
    /// The log epoch the position belongs to.
    pub epoch: u64,
    /// Deliver the rows after this sequence number.
    pub after_seq: u64,
    /// Events the client may expect were skipped.
    pub truncated: bool,
}

/// What a retention pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub evicted: u64,
    pub floor: u64,
}

/// The fence and expiry of the events owner's lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterLease {
    pub fence: u64,
    pub expires_at_ms: u64,
}

/// Keys of one source key's log.
#[derive(Debug, Clone)]
struct LogKeys {
    sk: String,
}

impl LogKeys {
    fn new(sk: &str) -> Self {
        Self { sk: sk.to_owned() }
    }
    fn head(&self) -> String {
        format!("ev:head:{}", self.sk)
    }
    fn row(&self, seq: u64) -> String {
        format!("ev:log:{}:{seq:020}", self.sk)
    }
    fn eid(&self, hashed: &str) -> String {
        format!("ev:eid:{}:{hashed}", self.sk)
    }
    fn epoch(&self) -> String {
        format!("ev:epoch:{}", self.sk)
    }
    fn floor(&self) -> String {
        format!("ev:floor:{}", self.sk)
    }
    fn inbox_counter(&self) -> String {
        format!("ev:in:n:{}", self.sk)
    }
    fn inbox_drained(&self) -> String {
        format!("ev:in:d:{}", self.sk)
    }
    fn inbox_row(&self, n: u64) -> String {
        format!("ev:in:{}:{n:020}", self.sk)
    }
    fn resume(&self, slot: Option<&str>) -> String {
        match slot {
            None => format!("ev:resume:{}", self.sk),
            Some(slot) => format!("ev:resume:{}:{slot}", self.sk),
        }
    }
}

/// The resume position of a source: the `upstream_cursor` of the last
/// occurrence it appended.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumeRecord {
    v: u32,
    cursor: serde_json::Value,
    at_ms: u64,
}

/// The schemas of an event type the log has seen, newest last, each with
/// the schema epoch it was given.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SchemaHistory {
    v: u32,
    entries: Vec<SchemaEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SchemaEntry {
    fingerprint: String,
    epoch: u32,
    input_schema: serde_json::Value,
    payload_schema: serde_json::Value,
}

/// Schema versions remembered per type: enough for a rolling update that
/// runs two configs at once to give each the same epoch.
const SCHEMA_HISTORY: usize = 8;

/// The key an occurrence is deduplicated by: its event id with the
/// recipients it is limited to, so one upstream event reported for two
/// sets of arguments is kept for each.
fn dedup_key(keys: &EventsKeys, occurrence: &StoredOccurrence) -> String {
    if occurrence.audience.is_none() && occurrence.arguments.is_none() {
        return keys.key_hash("event-id", occurrence.event_id.as_bytes());
    }
    keys.key_hash(
        "event-id",
        &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&serde_json::json!([
            occurrence.event_id,
            occurrence.audience,
            occurrence.arguments
        ])),
    )
}

fn encode<T: Serialize>(value: &T) -> Result<Bytes, LogError> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|e| LogError::Codec(e.to_string()))
}

/// Decode a versioned value; `Ok(None)` for a version newer than this
/// build reads.
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<Option<T>, LogError> {
    #[derive(Deserialize)]
    struct Version {
        v: u32,
    }
    let version: Version =
        serde_json::from_slice(bytes).map_err(|e| LogError::Codec(e.to_string()))?;
    if version.v > FORMAT_VERSION {
        return Ok(None);
    }
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|e| LogError::Codec(e.to_string()))
}

/// The event log over one `event-log` store.
pub struct EventLog {
    kv: Arc<dyn KeyValueStore>,
    bus: Option<Arc<dyn PubSub>>,
    keys: Arc<EventsKeys>,
    heads: Mutex<HashMap<String, watch::Sender<u64>>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    holes: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    rows: Mutex<HashMap<String, RowCache>>,
    /// The bounds last read of each log, and when.
    bounds_seen: Mutex<HashMap<String, (LogBounds, Instant)>>,
}

impl std::fmt::Debug for EventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLog").finish_non_exhaustive()
    }
}

impl EventLog {
    pub fn new(
        kv: Arc<dyn KeyValueStore>,
        bus: Option<Arc<dyn PubSub>>,
        keys: Arc<EventsKeys>,
    ) -> Self {
        Self {
            kv,
            bus,
            keys,
            heads: Mutex::new(HashMap::new()),
            locks: Mutex::new(HashMap::new()),
            holes: Mutex::new(HashMap::new()),
            rows: Mutex::new(HashMap::new()),
            bounds_seen: Mutex::new(HashMap::new()),
        }
    }

    fn cached_row(&self, sk: &str, seq: u64) -> Option<Arc<LogRow>> {
        self.rows
            .lock()
            .get(sk)
            .and_then(|cache| cache.rows.get(&seq).cloned())
    }

    /// Every row from `start` to `end` when memory holds them all.
    fn cached_rows(&self, sk: &str, start: u64, end: u64) -> Option<Vec<LogEntry>> {
        let rows: Vec<Arc<LogRow>> = {
            let caches = self.rows.lock();
            let cache = caches.get(sk)?;
            cache
                .rows
                .range(start..=end)
                .map(|(_, row)| Arc::clone(row))
                .collect()
        };
        (rows.len() as u64 == (end - start).saturating_add(1)).then(|| {
            rows.into_iter()
                .map(|row| LogEntry::Row((*row).clone()))
                .collect()
        })
    }

    fn cache_row(&self, sk: &str, row: LogRow) {
        self.rows
            .lock()
            .entry(sk.to_owned())
            .or_default()
            .insert(row);
    }

    /// The keys this log hashes with and seals cursors under.
    pub fn keys(&self) -> &Arc<EventsKeys> {
        &self.keys
    }

    /// A versioned value other than a row. One of a newer format fails the
    /// operation: guessing at a head or a drain position could overwrite
    /// what a newer build wrote.
    async fn get_value<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, LogError> {
        match self.kv.get(key).await? {
            None => Ok(None),
            Some(entry) => match decode(&entry.bytes)? {
                Some(value) => Ok(Some(value)),
                None => Err(LogError::NewerFormat),
            },
        }
    }

    /// The committed head, `None` for a log never written.
    pub async fn head(&self, sk: &str) -> Result<Option<HeadRecord>, LogError> {
        self.get_value(&LogKeys::new(sk).head()).await
    }

    /// The log's epoch, created on first use.
    pub async fn epoch(&self, sk: &str) -> Result<u64, LogError> {
        let key = LogKeys::new(sk).epoch();
        if let Some(record) = self.get_value::<EpochRecord>(&key).await? {
            return Ok(record.epoch);
        }
        let fresh = loop {
            use chacha20poly1305::aead::Generate as _;
            let candidate = u64::from_be_bytes(<[u8; 8]>::generate());
            if candidate != 0 {
                break candidate;
            }
        };
        let record = EpochRecord {
            v: FORMAT_VERSION,
            epoch: fresh,
        };
        if self.kv.put_if_absent(&key, encode(&record)?, None).await? {
            return Ok(fresh);
        }
        self.get_value::<EpochRecord>(&key)
            .await?
            .map(|r| r.epoch)
            .ok_or_else(|| LogError::Codec("event log epoch vanished while being created".into()))
    }

    /// The lowest retained sequence number.
    pub async fn floor(&self, sk: &str) -> Result<u64, LogError> {
        Ok(self
            .get_value::<FloorRecord>(&LogKeys::new(sk).floor())
            .await?
            .map_or(1, |f| f.floor.max(1)))
    }

    /// Epoch, floor and head of the log.
    pub async fn bounds(&self, sk: &str) -> Result<LogBounds, LogError> {
        let epoch = self.epoch(sk).await?;
        let head = self.head(sk).await?.map_or(0, |h| h.seq);
        let floor = self.floor(sk).await?;
        let bounds = LogBounds { epoch, floor, head };
        self.rows
            .lock()
            .entry(sk.to_owned())
            .or_default()
            .keep_epoch(epoch);
        self.bounds_seen
            .lock()
            .insert(sk.to_owned(), (bounds, Instant::now()));
        Ok(bounds)
    }

    /// Bounds whose head is at least `head`: those this process read last,
    /// when they reach it and are at most [`BOUNDS_FRESH`] old, else read
    /// now. The streams of a log share one read of its bounds this way.
    pub async fn bounds_since(&self, sk: &str, head: u64) -> Result<LogBounds, LogError> {
        let seen = self.bounds_seen.lock().get(sk).copied();
        match seen {
            Some((bounds, at)) if bounds.head >= head && at.elapsed() <= BOUNDS_FRESH => Ok(bounds),
            _ => self.bounds(sk).await,
        }
    }

    /// The row at `seq`, if it is still there.
    pub async fn get(&self, sk: &str, seq: u64) -> Result<Option<LogEntry>, LogError> {
        if let Some(row) = self.cached_row(sk, seq) {
            return Ok(Some(LogEntry::Row((*row).clone())));
        }
        self.fetch(sk, seq).await
    }

    /// The row at `seq` as the store holds it.
    async fn fetch(&self, sk: &str, seq: u64) -> Result<Option<LogEntry>, LogError> {
        match self.kv.get(&LogKeys::new(sk).row(seq)).await? {
            None => Ok(None),
            Some(entry) => Ok(Some(match decode::<LogRow>(&entry.bytes)? {
                Some(row) => {
                    self.cache_row(sk, row.clone());
                    LogEntry::Row(row)
                }
                None => LogEntry::Unreadable { seq },
            })),
        }
    }

    /// Up to `max` rows after `after`, never past the head and never
    /// below the floor. Missing rows are skipped.
    pub async fn read(&self, sk: &str, after: u64, max: usize) -> Result<Vec<LogEntry>, LogError> {
        let head = self.head(sk).await?.map_or(0, |h| h.seq);
        let floor = self.floor(sk).await?;
        let start = after.saturating_add(1).max(floor);
        let end = head.min(after.saturating_add(max as u64));
        self.read_rows(sk, start, end).await
    }

    /// The rows from `start` to `end`, both included, that are still there,
    /// for a reader that read the bounds itself; [`PARALLEL_OPS`] at once.
    /// One reader of a log reads the rows memory lacks at a time, so the
    /// streams a head wakes together read each row from the store once.
    pub async fn read_rows(
        &self,
        sk: &str,
        start: u64,
        end: u64,
    ) -> Result<Vec<LogEntry>, LogError> {
        if start > end {
            return Ok(Vec::new());
        }
        if let Some(rows) = self.cached_rows(sk, start, end) {
            return Ok(rows);
        }
        let fill = self.lock_for(&format!("fill:{sk}"));
        let _fill = fill.lock().await;
        let rows: Vec<Option<LogEntry>> = futures::stream::iter(start..=end)
            .map(|seq| self.get(sk, seq))
            .buffered(PARALLEL_OPS)
            .try_collect()
            .await?;
        Ok(rows.into_iter().flatten().collect())
    }

    /// Where a reader with `cursor` starts.
    ///
    /// A missing, unopenable, foreign or stale cursor starts at the head as
    /// [`CursorCodec::resume`](super::cursor::CursorCodec::resume) decides;
    /// `max_age_ms` then moves the start to the first row at most that old,
    /// and a gap marker between the start and the head also reports
    /// `truncated`. `Err(None)` reports a cursor from an older schema
    /// epoch, which the caller answers with a schema-changed error.
    pub async fn resume(
        &self,
        sk: &str,
        cursor: Option<&str>,
        scope: &CursorScope,
        schema_epoch: u32,
        max_age_ms: Option<u64>,
    ) -> Result<Result<ResumePoint, SchemaChanged>, LogError> {
        let bounds = self.bounds(sk).await?;
        let (mut after, mut truncated) =
            match self
                .keys
                .cursor()
                .resume(cursor, scope, bounds, schema_epoch)
            {
                Resume::After { seq, truncated } => (seq, truncated),
                Resume::SchemaChanged => return Ok(Err(SchemaChanged)),
            };
        if let Some(max_age) = max_age_ms {
            let cutoff = now_ms().saturating_sub(max_age);
            let first = self.first_at_or_after(sk, bounds, after, cutoff).await?;
            if first > after.saturating_add(1) {
                after = first - 1;
                truncated = true;
            }
        }
        let last_gap = self.head(sk).await?.map_or(0, |h| h.last_gap_seq);
        if cursor.is_some() && last_gap > after {
            truncated = true;
        }
        Ok(Ok(ResumePoint {
            epoch: bounds.epoch,
            after_seq: after,
            truncated,
        }))
    }

    /// First sequence number after `after` whose row was appended at or
    /// after `cutoff_ms`; `head + 1` when none. Rows are appended in time
    /// order by one writer, so a binary search over the range holds.
    async fn first_at_or_after(
        &self,
        sk: &str,
        bounds: LogBounds,
        after: u64,
        cutoff_ms: u64,
    ) -> Result<u64, LogError> {
        let mut lo = after.saturating_add(1).max(bounds.floor);
        let mut hi = bounds.head.saturating_add(1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let mut probe = mid;
            let mut at = None;
            while probe < hi {
                if let Some(LogEntry::Row(row)) = self.get(sk, probe).await? {
                    at = Some(row.appended_at_ms);
                    break;
                }
                probe += 1;
            }
            match at {
                Some(ms) if ms >= cutoff_ms => hi = mid,
                Some(_) => lo = probe + 1,
                None => hi = mid,
            }
        }
        Ok(lo)
    }

    /// The sealed cursor of `seq` in epoch `epoch`.
    pub fn seal_cursor(
        &self,
        epoch: u64,
        schema_epoch: u32,
        seq: u64,
        scope: &CursorScope,
    ) -> String {
        self.keys.cursor().seal(
            CursorPosition {
                epoch,
                schema_epoch,
                seq,
            },
            scope,
        )
    }

    /// A receiver of the head of `sk` as this process's writer moves it.
    pub fn watch_head(&self, sk: &str) -> watch::Receiver<u64> {
        self.heads
            .lock()
            .entry(sk.to_owned())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    fn announce_head(&self, sk: &str, seq: u64) {
        if let Some(tx) = self.heads.lock().get(sk) {
            tx.send_replace(seq);
        }
        if let Some(bus) = self.bus.clone() {
            let topic = format!("{HEAD_TOPIC_PREFIX}{sk}");
            tokio::spawn(async move {
                let _ = bus.publish(&topic, Bytes::from(seq.to_string())).await;
            });
        }
    }

    fn lock_for(&self, sk: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.locks
                .lock()
                .entry(sk.to_owned())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    // -----------------------------------------------------------------------
    // Resume positions and schema epochs
    // -----------------------------------------------------------------------

    /// Where the source of `sk` resumes: the upstream cursor of the last
    /// occurrence it appended. `slot` names one of several positions of a
    /// source that reads the upstream more than once, such as one per set
    /// of arguments.
    pub async fn resume_position(
        &self,
        sk: &str,
        slot: Option<&str>,
    ) -> Result<Option<serde_json::Value>, LogError> {
        Ok(self
            .get_value::<ResumeRecord>(&LogKeys::new(sk).resume(slot))
            .await?
            .map(|r| r.cursor))
    }

    /// Remember `cursor` as where the source of `sk` resumes, for `ttl`
    /// or for good.
    pub async fn store_resume_position(
        &self,
        sk: &str,
        slot: Option<&str>,
        cursor: serde_json::Value,
        ttl: Option<Duration>,
    ) -> Result<(), LogError> {
        let record = ResumeRecord {
            v: FORMAT_VERSION,
            cursor,
            at_ms: now_ms(),
        };
        self.kv
            .put(&LogKeys::new(sk).resume(slot), encode(&record)?, ttl)
            .await?;
        Ok(())
    }

    /// The schema epoch of event type `name` under these schemas. The epoch
    /// moves only when a schema changes in a way a subscriber cannot absorb
    /// ([`is_additive_change`] says no), so a cursor or a subscription of
    /// the previous epoch is refused rather than misread. Schemas seen
    /// before keep the epoch they were given, so two configs live at once
    /// during a rolling update agree on theirs.
    pub async fn schema_epoch(
        &self,
        name: &str,
        input_schema: &serde_json::Value,
        payload_schema: &serde_json::Value,
    ) -> Result<u32, LogError> {
        let key = format!(
            "ev:schema:{}",
            self.keys.key_hash("event-type", name.as_bytes())
        );
        let fingerprint = hex::encode(hmac_sha256::Hash::hash(
            &mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&serde_json::json!([
                input_schema,
                payload_schema
            ])),
        ));
        let mut history = self
            .get_value::<SchemaHistory>(&key)
            .await?
            .unwrap_or_default();
        if let Some(seen) = history
            .entries
            .iter()
            .find(|e| e.fingerprint == fingerprint)
        {
            return Ok(seen.epoch);
        }
        let epoch = match history.entries.last() {
            None => 0,
            Some(latest)
                if is_additive_change(&latest.input_schema, input_schema, SchemaRole::Input)
                    && is_additive_change(
                        &latest.payload_schema,
                        payload_schema,
                        SchemaRole::Payload,
                    ) =>
            {
                latest.epoch
            }
            Some(_) => history
                .entries
                .iter()
                .map(|e| e.epoch)
                .max()
                .unwrap_or(0)
                .saturating_add(1),
        };
        history.v = FORMAT_VERSION;
        history.entries.push(SchemaEntry {
            fingerprint,
            epoch,
            input_schema: input_schema.clone(),
            payload_schema: payload_schema.clone(),
        });
        let excess = history.entries.len().saturating_sub(SCHEMA_HISTORY);
        history.entries.drain(..excess);
        self.kv.put(&key, encode(&history)?, None).await?;
        Ok(epoch)
    }

    // -----------------------------------------------------------------------
    // Inbox (any replica)
    // -----------------------------------------------------------------------

    /// Write `row` to the inbox of `sk`, unless the inbox is full or no
    /// writer has drained it within the inbox TTL.
    pub async fn inbox_put(
        &self,
        sk: &str,
        row: InboxRow,
        limits: InboxLimits,
    ) -> Result<InboxOutcome, LogError> {
        let keys = LogKeys::new(sk);
        let now = now_ms();
        let drained = match self
            .get_value::<InboxDrained>(&keys.inbox_drained())
            .await?
        {
            Some(drained) => drained,
            None => {
                let initial = InboxDrained {
                    v: FORMAT_VERSION,
                    n: 0,
                    at_ms: now,
                };
                self.kv
                    .put_if_absent(&keys.inbox_drained(), encode(&initial)?, None)
                    .await?;
                self.get_value(&keys.inbox_drained())
                    .await?
                    .unwrap_or(initial)
            }
        };
        let written = self.inbox_written(&keys).await?;
        let pending = written.saturating_sub(drained.n);
        let ttl_ms = limits.ttl.as_millis() as u64;
        let stale = pending > 0 && now.saturating_sub(drained.at_ms) > ttl_ms;
        if pending >= limits.max_rows || stale {
            metrics::counter!("mcpg_events_inbox_full_total").increment(1);
            return Ok(InboxOutcome::Full {
                retry_after: Duration::from_secs(60),
            });
        }
        let n = self.kv.incr(&keys.inbox_counter(), 1, None).await?;
        let n = u64::try_from(n).map_err(|_| LogError::Codec("negative inbox counter".into()))?;
        self.kv
            .put(&keys.inbox_row(n), encode(&row)?, Some(limits.ttl))
            .await?;
        if let Some(bus) = &self.bus {
            let _ = bus
                .publish(INBOX_TOPIC, Bytes::copy_from_slice(sk.as_bytes()))
                .await;
        }
        Ok(InboxOutcome::Accepted)
    }

    // -----------------------------------------------------------------------
    // Writer (events owner only)
    // -----------------------------------------------------------------------

    /// Append `occurrence` to the log of `sk` under `lease`.
    pub async fn append(
        &self,
        sk: &str,
        occurrence: StoredOccurrence,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<AppendOutcome, LogError> {
        let lock = self.lock_for(sk);
        let _guard = lock.lock().await;
        let keys = LogKeys::new(sk);
        let eid = dedup_key(&self.keys, &occurrence);
        if self.kv.get(&keys.eid(&eid)).await?.is_some() {
            metrics::counter!("mcpg_events_deduped_total").increment(1);
            return Ok(AppendOutcome::Duplicate);
        }
        let (seq, bytes) = self
            .append_locked(&keys, RowBody::Event(occurrence), retention, lease)
            .await?;
        let marker = DedupMarker {
            v: FORMAT_VERSION,
            seq,
        };
        self.kv
            .put_if_absent(&keys.eid(&eid), encode(&marker)?, Some(row_ttl(retention)))
            .await?;
        metrics::counter!("mcpg_events_appended_total").increment(1);
        Ok(AppendOutcome::Appended { seq, bytes })
    }

    /// Append `occurrences` in order, each as [`Self::append`] would, under
    /// one hold of the log: their dedup markers read at once, the head read
    /// once and moved after every [`HEAD_EVERY`] rows, the new markers
    /// written at once once the head covers their rows. A failure leaves the
    /// rows before it committed and marked, so a drain that runs the same
    /// inbox rows again appends none of them twice.
    pub async fn append_many(
        &self,
        sk: &str,
        occurrences: Vec<StoredOccurrence>,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<Vec<AppendOutcome>, LogError> {
        if occurrences.is_empty() {
            return Ok(Vec::new());
        }
        let lock = self.lock_for(sk);
        let _guard = lock.lock().await;
        let keys = LogKeys::new(sk);
        let eids: Vec<String> = occurrences
            .iter()
            .map(|occurrence| dedup_key(&self.keys, occurrence))
            .collect();
        let markers: Vec<String> = eids.iter().map(|eid| keys.eid(eid)).collect();
        let seen: Vec<bool> = futures::stream::iter(markers)
            .map(|key| async move { self.kv.get(&key).await.map(|found| found.is_some()) })
            .buffered(PARALLEL_OPS)
            .try_collect()
            .await?;
        let now = now_ms();
        if lease.expires_at_ms <= now {
            return Err(LogError::LeaseExpired);
        }
        let mut head = self.writer_head(&keys, lease, now).await?;
        let mut in_batch = HashSet::new();
        let mut outcomes = Vec::with_capacity(occurrences.len());
        let mut unmarked: Vec<(String, u64)> = Vec::new();
        let mut written = 0usize;
        for ((occurrence, eid), seen) in occurrences.into_iter().zip(eids).zip(seen) {
            if seen || !in_batch.insert(eid.clone()) {
                metrics::counter!("mcpg_events_deduped_total").increment(1);
                outcomes.push(AppendOutcome::Duplicate);
                continue;
            }
            let row = if lease.expires_at_ms <= now_ms() {
                Err(LogError::LeaseExpired)
            } else {
                self.write_row(
                    &keys,
                    &mut head,
                    RowBody::Event(occurrence),
                    retention,
                    lease,
                    now,
                )
                .await
            };
            let (seq, bytes) = match row {
                Ok(row) => row,
                Err(error) => {
                    if written > 0 {
                        // Best effort: the error below is what the caller acts on.
                        let _ = self
                            .commit_marked(&keys, &head, &mut unmarked, retention, lease)
                            .await;
                    }
                    return Err(error);
                }
            };
            metrics::counter!("mcpg_events_appended_total").increment(1);
            outcomes.push(AppendOutcome::Appended { seq, bytes });
            unmarked.push((eid, seq));
            written += 1;
            if unmarked.len() >= HEAD_EVERY {
                self.commit_marked(&keys, &head, &mut unmarked, retention, lease)
                    .await?;
            }
        }
        if !unmarked.is_empty() {
            self.commit_marked(&keys, &head, &mut unmarked, retention, lease)
                .await?;
        }
        Ok(outcomes)
    }

    /// Commit `head`, then write the dedup markers of the rows it now
    /// covers. Not past `lease`: an expired writer leaves its rows for the
    /// next one to adopt.
    async fn commit_marked(
        &self,
        keys: &LogKeys,
        head: &HeadRecord,
        unmarked: &mut Vec<(String, u64)>,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<(), LogError> {
        if lease.expires_at_ms <= now_ms() {
            return Err(LogError::LeaseExpired);
        }
        self.commit_head(keys, head).await?;
        let ttl = Some(row_ttl(retention));
        let markers = std::mem::take(unmarked);
        futures::stream::iter(markers)
            .map(|(eid, seq)| async move {
                let marker = encode(&DedupMarker {
                    v: FORMAT_VERSION,
                    seq,
                })?;
                self.kv
                    .put_if_absent(&keys.eid(&eid), marker, ttl)
                    .await
                    .map_err(LogError::from)
            })
            .buffered(PARALLEL_OPS)
            .try_collect::<Vec<bool>>()
            .await?;
        Ok(())
    }

    /// Append a gap marker for the readers of `scope` to the log of `sk`.
    pub async fn append_gap(
        &self,
        sk: &str,
        reason: GapReason,
        scope: RowScope,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<u64, LogError> {
        self.append_marker(sk, RowBody::Gap { reason, scope }, retention, lease)
            .await
    }

    /// Append the end of the subscriptions of the readers of `scope` to the
    /// log of `sk`.
    pub async fn append_end(
        &self,
        sk: &str,
        reason: EndReason,
        scope: RowScope,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<u64, LogError> {
        self.append_marker(sk, RowBody::Ended { reason, scope }, retention, lease)
            .await
    }

    async fn append_marker(
        &self,
        sk: &str,
        body: RowBody,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<u64, LogError> {
        let lock = self.lock_for(sk);
        let _guard = lock.lock().await;
        self.append_locked(&LogKeys::new(sk), body, retention, lease)
            .await
            .map(|(seq, _)| seq)
    }

    /// Append `body` as the next row; returns its sequence number and its
    /// encoded size.
    async fn append_locked(
        &self,
        keys: &LogKeys,
        body: RowBody,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<(u64, u64), LogError> {
        let now = now_ms();
        if lease.expires_at_ms <= now {
            return Err(LogError::LeaseExpired);
        }
        let mut head = self.writer_head(keys, lease, now).await?;
        let written = self
            .write_row(keys, &mut head, body, retention, lease, now)
            .await?;
        self.commit_head(keys, &head).await?;
        Ok(written)
    }

    /// The committed head for a writer under `lease`; `Deposed` when
    /// another writer holds a newer fence.
    async fn writer_head(
        &self,
        keys: &LogKeys,
        lease: WriterLease,
        now: u64,
    ) -> Result<HeadRecord, LogError> {
        let head = self
            .get_value::<HeadRecord>(&keys.head())
            .await?
            .unwrap_or_default();
        if head.fence > lease.fence && head.lease_expires_at_ms > now {
            return Err(LogError::Deposed);
        }
        Ok(head)
    }

    /// Write `body` as the row after `head` and move `head` over it, in
    /// memory only: [`Self::commit_head`] makes it the committed head.
    async fn write_row(
        &self,
        keys: &LogKeys,
        head: &mut HeadRecord,
        body: RowBody,
        retention: &EventRetentionConfig,
        lease: WriterLease,
        now: u64,
    ) -> Result<(u64, u64), LogError> {
        let is_gap = matches!(&body, RowBody::Gap { scope, .. } if is_every_reader(scope));
        loop {
            let seq = head.seq + 1;
            let mut row = LogRow {
                v: FORMAT_VERSION,
                seq,
                appended_at_ms: now,
                bytes: 0,
                body: body.clone(),
            };
            row.bytes = encode(&row)?.len() as u64;
            let encoded = encode(&row)?;
            let ttl = row_ttl(retention);
            if self
                .kv
                .put_if_absent(&keys.row(seq), encoded, Some(ttl))
                .await?
            {
                head.v = FORMAT_VERSION;
                head.seq = seq;
                head.fence = lease.fence;
                head.lease_expires_at_ms = lease.expires_at_ms;
                head.bytes = head.bytes.saturating_add(row.bytes);
                if is_gap {
                    head.last_gap_seq = seq;
                }
                let bytes = row.bytes;
                self.cache_row(&keys.sk, row);
                return Ok((seq, bytes));
            }
            // The slot is taken: a writer appended it and stopped before
            // moving the head, or another writer is appending now. Adopt the
            // row and re-read the head before trying the next slot.
            let taken = match self.fetch(&keys.sk, seq).await? {
                Some(LogEntry::Row(row)) => row.bytes,
                _ => 0,
            };
            let current = self
                .get_value::<HeadRecord>(&keys.head())
                .await?
                .unwrap_or_default();
            if current.fence > lease.fence && current.lease_expires_at_ms > now {
                return Err(LogError::Deposed);
            }
            if current.seq >= seq {
                *head = current;
            } else {
                head.seq = seq;
                head.bytes = head.bytes.saturating_add(taken);
            }
        }
    }

    /// Make `head` the committed head and tell the readers.
    async fn commit_head(&self, keys: &LogKeys, head: &HeadRecord) -> Result<(), LogError> {
        self.kv.put(&keys.head(), encode(head)?, None).await?;
        self.announce_head(&keys.sk, head.seq);
        Ok(())
    }

    /// Move inbox rows of `sk` into the log, in arrival order. `shape`
    /// builds each stored occurrence; `None` drops the row. `pass` tallies
    /// what the pass consumed and appended, also when it fails part way.
    pub async fn drain_inbox<F, Fut>(
        &self,
        sk: &str,
        retention: &EventRetentionConfig,
        lease: WriterLease,
        shape: F,
        pass: &mut InboxDrain,
    ) -> Result<(), LogError>
    where
        F: Fn(InboxRow) -> Fut,
        Fut: std::future::Future<Output = Option<StoredOccurrence>>,
    {
        let drain_lock = self.lock_for(&format!("drain:{sk}"));
        let _drain_guard = drain_lock.lock().await;
        let keys = LogKeys::new(sk);
        let now = now_ms();
        let mut drained = self
            .get_value::<InboxDrained>(&keys.inbox_drained())
            .await?
            .unwrap_or(InboxDrained {
                v: FORMAT_VERSION,
                n: 0,
                at_ms: now,
            });
        let written = self.inbox_written(&keys).await?;
        let end = written.min(drained.n.saturating_add(DRAIN_BATCH));
        let first = drained.n + 1;
        let fetched: Vec<Result<Option<InboxRow>, LogError>> =
            futures::stream::iter((first..=end).map(|n| keys.inbox_row(n)))
                .map(|key| async move { self.get_value::<InboxRow>(&key).await })
                .buffered(PARALLEL_OPS)
                .collect()
                .await;
        let mut n = drained.n;
        let mut events: Vec<InboxRow> = Vec::new();
        let mut taken: Vec<u64> = Vec::new();
        for (next, fetched) in (first..=end).zip(fetched) {
            match fetched {
                Ok(Some(row)) => {
                    self.holes.lock().remove(sk);
                    if let Some(marker) = row.marker {
                        // The events before the marker go first.
                        self.append_events(sk, &mut events, retention, lease, &shape, pass)
                            .await?;
                        let scope = RowScope {
                            audience: row.audience,
                            arguments: row.arguments,
                        };
                        let body = match marker {
                            InboxMarker::Gap { reason } => RowBody::Gap { reason, scope },
                            InboxMarker::Ended { reason } => RowBody::Ended { reason, scope },
                        };
                        self.append_marker(sk, body, retention, lease).await?;
                    } else {
                        events.push(row);
                    }
                    taken.push(next);
                }
                Ok(None) => {
                    // Reserved but not yet written, or expired: wait out the
                    // grace, then skip it.
                    let waited = {
                        let mut holes = self.holes.lock();
                        let entry = holes
                            .entry(sk.to_owned())
                            .or_insert((next, std::time::Instant::now()));
                        if entry.0 != next {
                            *entry = (next, std::time::Instant::now());
                        }
                        entry.1.elapsed()
                    };
                    if waited < INBOX_HOLE_GRACE {
                        break;
                    }
                    metrics::counter!("mcpg_events_inbox_skipped_total").increment(1);
                    self.holes.lock().remove(sk);
                }
                Err(LogError::Codec(_)) => {
                    metrics::counter!("mcpg_events_inbox_skipped_total").increment(1);
                    taken.push(next);
                }
                Err(LogError::NewerFormat) => {
                    tracing::warn!(
                        "an event inbox row of a newer format waits for an owner that reads it"
                    );
                    break;
                }
                Err(other) => return Err(other),
            }
            n = next;
            pass.consumed += 1;
        }
        self.append_events(sk, &mut events, retention, lease, &shape, pass)
            .await?;
        futures::stream::iter(taken.into_iter().map(|n| keys.inbox_row(n)))
            .map(|key| async move { self.kv.delete(&key).await })
            .buffered(PARALLEL_OPS)
            .try_collect::<Vec<bool>>()
            .await?;
        drained.v = FORMAT_VERSION;
        drained.n = n;
        drained.at_ms = now_ms();
        self.kv
            .put(&keys.inbox_drained(), encode(&drained)?, None)
            .await?;
        Ok(())
    }

    /// Shape the inbox `events` and append them in order; `shape` runs on
    /// [`PARALLEL_OPS`] rows at once and drops a row by answering `None`.
    async fn append_events<F, Fut>(
        &self,
        sk: &str,
        events: &mut Vec<InboxRow>,
        retention: &EventRetentionConfig,
        lease: WriterLease,
        shape: &F,
        pass: &mut InboxDrain,
    ) -> Result<(), LogError>
    where
        F: Fn(InboxRow) -> Fut,
        Fut: std::future::Future<Output = Option<StoredOccurrence>>,
    {
        if events.is_empty() {
            return Ok(());
        }
        let shaped: Vec<Fut> = std::mem::take(events).into_iter().map(shape).collect();
        let occurrences: Vec<StoredOccurrence> = futures::stream::iter(shaped)
            .buffered(PARALLEL_OPS)
            .filter_map(std::future::ready)
            .collect()
            .await;
        for outcome in self.append_many(sk, occurrences, retention, lease).await? {
            if let AppendOutcome::Appended { bytes, .. } = outcome {
                pass.appended += 1;
                pass.bytes = pass.bytes.saturating_add(bytes);
            }
        }
        Ok(())
    }

    /// Whether the inbox of `sk` holds rows not yet drained.
    pub async fn inbox_pending(&self, sk: &str) -> Result<u64, LogError> {
        let keys = LogKeys::new(sk);
        let drained = self
            .get_value::<InboxDrained>(&keys.inbox_drained())
            .await?
            .map_or(0, |d| d.n);
        let written = self.inbox_written(&keys).await?;
        Ok(written.saturating_sub(drained))
    }

    /// Rows ever written to the inbox of `keys`. Read through `incr` by
    /// zero: a counter stays plaintext under state encryption, which a `get`
    /// through the encrypting store refuses.
    async fn inbox_written(&self, keys: &LogKeys) -> Result<u64, LogError> {
        let n = self.kv.incr(&keys.inbox_counter(), 0, None).await?;
        Ok(u64::try_from(n).unwrap_or(0))
    }

    /// Evict the oldest rows of `sk` past any retention bound and move the
    /// floor. Never touches a row above the head.
    pub async fn enforce_retention(
        &self,
        sk: &str,
        retention: &EventRetentionConfig,
        lease: WriterLease,
    ) -> Result<RetentionReport, LogError> {
        let lock = self.lock_for(sk);
        let _guard = lock.lock().await;
        let keys = LogKeys::new(sk);
        let now = now_ms();
        if lease.expires_at_ms <= now {
            return Err(LogError::LeaseExpired);
        }
        let Some(mut head) = self.get_value::<HeadRecord>(&keys.head()).await? else {
            return Ok(RetentionReport::default());
        };
        if head.fence > lease.fence && head.lease_expires_at_ms > now {
            return Err(LogError::Deposed);
        }
        let max_bytes = retention.max_bytes_or_default();
        let cutoff = now.saturating_sub(retention.max_age_ms);
        let initial_floor = self.floor(sk).await?;
        let mut floor = initial_floor;
        let mut evict = Vec::new();
        while floor <= head.seq && (evict.len() as u64) < RETENTION_BATCH {
            let retained = head.seq - floor + 1;
            let row = self.get(sk, floor).await?;
            let over_count = retained > retention.max_events;
            let over_bytes = head.bytes > max_bytes;
            let (too_old, bytes) = match &row {
                Some(LogEntry::Row(row)) => (row.appended_at_ms < cutoff, row.bytes),
                Some(LogEntry::Unreadable { .. }) => (false, 0),
                // Already gone (store TTL or a hole): nothing to keep.
                None => (true, 0),
            };
            if !(over_count || over_bytes || too_old) {
                break;
            }
            if row.is_some() {
                evict.push(floor);
            }
            head.bytes = head.bytes.saturating_sub(bytes);
            floor += 1;
        }
        let evicted = evict.len() as u64;
        if floor > head.seq {
            head.bytes = 0;
        }
        if floor != initial_floor {
            let record = FloorRecord {
                v: FORMAT_VERSION,
                floor,
            };
            self.kv.put(&keys.floor(), encode(&record)?, None).await?;
            self.kv.put(&keys.head(), encode(&head)?, None).await?;
            for seq in evict {
                self.kv.delete(&keys.row(seq)).await?;
            }
            if let Some(cache) = self.rows.lock().get_mut(sk) {
                cache.drop_below(floor);
            }
            metrics::counter!("mcpg_events_evicted_total").increment(evicted);
        }
        Ok(RetentionReport { evicted, floor })
    }
}

/// A cursor from an older schema epoch than the type's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaChanged;

fn row_ttl(retention: &EventRetentionConfig) -> Duration {
    Duration::from_millis(retention.max_age_ms).saturating_add(ROW_TTL_GRACE)
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
