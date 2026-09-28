//! The file store of interactive sign-in state
//! (`governance.access.authorization_server.interactive.store.kind: file`,
//! the single-node default), and the state key generated next to it.
//!
//! Layout of the store directory:
//!
//! ```text
//! <dir>/
//!   lock          held by the one process that has the store open
//!   state.key     the generated state key, when no other key is configured
//!   records/      one file per record, named by a hash of its key
//!   tmp/          writes in progress
//!   corrupt/      records found damaged when the store opened
//! ```
//!
//! A write lands in `tmp/`, is flushed to disk, renamed over the record and
//! the directory entry is flushed, so a crash leaves the old record or the
//! new one, never part of either. Directories are created with mode 0700
//! and files with mode 0600 on unix, and a store directory or entry that
//! another user owns, or that is a symbolic link, is refused at open. Only
//! the process that holds `lock` opens the store, so the per-key in-process
//! locks that order the writes of one key make [`KeyValueStore::put_if_absent`] and
//! [`KeyValueStore::incr`] atomic. Expired records are swept every
//! [`SWEEP_INTERVAL`], and a new record beyond [`FileStoreLimits`] is
//! refused. The values are sealed by the state keyring before they reach
//! this store.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use mcpg_cluster_api::{ClusterError, Entry, KeyValueStore};
use parking_lot::Mutex;
use zeroize::Zeroizing;

/// Name of the file every open store holds an exclusive lock on.
pub const LOCK_FILE: &str = "lock";
const RECORDS_DIR: &str = "records";
const TMP_DIR: &str = "tmp";
const CORRUPT_DIR: &str = "corrupt";
const RECORD_EXTENSION: &str = "rec";
const PROBE_NAME: &str = "write-probe";
/// First bytes of every record file.
const RECORD_MAGIC: &[u8; 8] = b"MCPGAS01";
const CHECKSUM_BYTES: usize = 32;
/// Writes of different keys run in parallel across this many locks.
const WRITE_LOCKS: usize = 16;
/// How often expired records are removed.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Bytes of a state key.
pub const STATE_KEY_BYTES: usize = 32;

/// How much a file store holds. A new record beyond a limit is refused
/// with [`ClusterError::Precondition`] after the expired records are
/// removed; replacing a record never is, unless its value alone is too
/// large.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStoreLimits {
    /// Records held at once.
    pub max_records: usize,
    /// Bytes of one value.
    pub max_value_bytes: usize,
    /// Bytes of every record file together.
    pub max_total_bytes: u64,
}

impl Default for FileStoreLimits {
    fn default() -> Self {
        Self {
            max_records: 200_000,
            max_value_bytes: 128 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

/// A [`KeyValueStore`] in a directory on local disk, for one process.
#[derive(Clone)]
pub struct FileStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("dir", &self.inner.root)
            .field("records", &self.inner.index.lock().entries.len())
            .finish()
    }
}

struct Inner {
    root: PathBuf,
    records: PathBuf,
    tmp: PathBuf,
    limits: FileStoreLimits,
    index: Mutex<Index>,
    write_locks: Vec<Mutex<()>>,
    /// Holds the exclusive lock on [`LOCK_FILE`] while the store is open.
    _lock: File,
}

/// Every live record's key, expiry and file size. The process holding the
/// lock is the only writer, so the index is the store's truth for which
/// keys exist; the files hold the values.
#[derive(Default)]
struct Index {
    entries: BTreeMap<String, IndexEntry>,
    bytes: u64,
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    expires_ms: Option<u64>,
    size: u64,
}

impl IndexEntry {
    fn live(&self, now_ms: u64) -> bool {
        self.expires_ms.is_none_or(|at| at > now_ms)
    }
}

impl Index {
    fn insert(&mut self, key: String, entry: IndexEntry) {
        if let Some(old) = self.entries.insert(key, entry) {
            self.bytes = self.bytes.saturating_sub(old.size);
        }
        self.bytes += entry.size;
    }

    fn remove(&mut self, key: &str) {
        if let Some(old) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(old.size);
        }
    }

    fn live(&self, key: &str, now_ms: u64) -> Option<IndexEntry> {
        self.entries
            .get(key)
            .copied()
            .filter(|entry| entry.live(now_ms))
    }
}

struct Record {
    key: String,
    expires_ms: Option<u64>,
    value: Vec<u8>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn expiry_ms(now: u64, ttl: Option<Duration>) -> Option<u64> {
    ttl.map(|ttl| now.saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX).max(1)))
}

fn to_system_time(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// File name of the record under `key`: a hash, so a key never shapes a
/// path.
fn record_name(key: &str) -> String {
    let digest = blake3::derive_key("mcpg as file store v1 record name", key.as_bytes());
    format!("{}.{RECORD_EXTENSION}", hex::encode(digest))
}

/// Bytes of the file holding a record of `key` and `value_len` bytes.
fn record_size(key: &str, value_len: usize) -> u64 {
    (RECORD_MAGIC.len() + 8 + 4 + key.len() + 4 + value_len + CHECKSUM_BYTES) as u64
}

fn encode_record(key: &str, expires_ms: Option<u64>, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(record_size(key, value.len()) as usize);
    out.extend_from_slice(RECORD_MAGIC);
    out.extend_from_slice(&expires_ms.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
    let checksum = blake3::hash(&out);
    out.extend_from_slice(checksum.as_bytes());
    out
}

fn decode_record(bytes: &[u8]) -> Option<Record> {
    let body_len = bytes.len().checked_sub(CHECKSUM_BYTES)?;
    let (body, checksum) = bytes.split_at(body_len);
    if blake3::hash(body).as_bytes() != checksum {
        return None;
    }
    let rest = body.strip_prefix(RECORD_MAGIC.as_slice())?;
    let (expires, rest) = rest.split_first_chunk::<8>()?;
    let (key_len, rest) = rest.split_first_chunk::<4>()?;
    let key_len = u32::from_le_bytes(*key_len) as usize;
    if rest.len() < key_len {
        return None;
    }
    let (key, rest) = rest.split_at(key_len);
    let (value_len, value) = rest.split_first_chunk::<4>()?;
    if value.len() != u32::from_le_bytes(*value_len) as usize {
        return None;
    }
    let expires = u64::from_le_bytes(*expires);
    Some(Record {
        key: std::str::from_utf8(key).ok()?.to_owned(),
        expires_ms: (expires != 0).then_some(expires),
        value: value.to_vec(),
    })
}

fn unavailable(action: &str, path: &Path, error: &io::Error) -> ClusterError {
    ClusterError::BackendUnavailable {
        reason: format!("sign-in store: {action} {}: {error}", path.display()),
    }
}

/// Create `dir` and its missing parents, readable by this user only.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// This process's effective user id.
#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Refuse the entry at `path`, described by `meta` (not following a
/// symbolic link), unless it is a directory (`directory`) or a regular file
/// that this process's user owns. A user who owns an entry of the store can
/// read what it holds or replace it.
#[cfg(unix)]
fn check_owned(path: &Path, meta: &fs::Metadata, directory: bool) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let described = path.display();
    if meta.file_type().is_symlink() {
        anyhow::bail!("{described} in the sign-in store is a symbolic link; remove it");
    }
    if directory && !meta.is_dir() {
        anyhow::bail!("{described} in the sign-in store is not a directory");
    }
    if !directory && !meta.is_file() {
        anyhow::bail!("{described} in the sign-in store is not a regular file");
    }
    let euid = effective_uid();
    if meta.uid() != euid {
        anyhow::bail!(
            "{described} belongs to uid {}, not to the gateway's user (uid {euid}), who then \
             cannot keep the sign-in state in it private; remove it, or point \
             interactive.store.dir at a directory the gateway's user creates",
            meta.uid()
        );
    }
    Ok(())
}

/// Create the directory `dir` when absent, refuse it unless it is a
/// directory this user owns, and restrict it to mode 0700.
fn prepare_private_dir(dir: &Path) -> anyhow::Result<()> {
    let described = dir.display();
    create_private_dir(dir)
        .map_err(|e| anyhow::anyhow!("cannot create {described} in the sign-in store: {e}"))?;
    #[cfg(unix)]
    {
        let meta = fs::symlink_metadata(dir)
            .map_err(|e| anyhow::anyhow!("cannot inspect {described}: {e}"))?;
        check_owned(dir, &meta, true)?;
    }
    if restrict_permissions(dir, 0o700)
        .map_err(|e| anyhow::anyhow!("cannot restrict {described} to its owner: {e}"))?
    {
        tracing::warn!(
            dir = %described,
            "a sign-in store directory was open to other users; restricted it to mode 0700"
        );
    }
    Ok(())
}

/// Remove group and other access from `path`, which must then be `mode`.
/// A path already that private is left alone.
#[cfg(unix)]
fn restrict_permissions(path: &Path, mode: u32) -> io::Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    let current = fs::metadata(path)?.permissions().mode() & 0o777;
    if current & 0o077 == 0 {
        return Ok(false);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(true)
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path, _mode: u32) -> io::Result<bool> {
    Ok(false)
}

/// Open a new file for writing, readable by this user only.
fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Flush the entries of `dir` to disk, so a rename or removal in it
/// survives a crash. Windows has no handle to a directory to flush.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Write `bytes` to `path` through `tmp`: flushed, renamed into place,
/// and the directory entry flushed.
fn write_atomically(tmp: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Err(error) = fs::remove_file(tmp)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(error);
    }
    let written = create_private_file(tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| fs::rename(tmp, path)) {
        let _ = fs::remove_file(tmp);
        return Err(error);
    }
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

impl FileStore {
    /// Open the store in `dir`, creating it when absent. Refused when
    /// another process has it open, when it cannot be written, or (on unix)
    /// when the directory or an entry of it is another user's or a symbolic
    /// link. The directories are restricted to mode 0700, the expired
    /// records are removed and damaged ones moved to `corrupt/`.
    pub fn open(dir: &Path, limits: FileStoreLimits) -> anyhow::Result<Self> {
        let described = dir.display();
        create_private_dir(dir)
            .map_err(|e| anyhow::anyhow!("cannot create the sign-in store {described}: {e}"))?;
        let root = fs::canonicalize(dir)
            .map_err(|e| anyhow::anyhow!("cannot resolve the sign-in store {described}: {e}"))?;
        // The root first: once it is this user's and 0700, no other user
        // can swap the entries checked after it.
        prepare_private_dir(&root)?;
        let lock = open_lock(&root)?;
        let records = root.join(RECORDS_DIR);
        let tmp = root.join(TMP_DIR);
        for sub in [&records, &tmp] {
            prepare_private_dir(sub)?;
        }
        clear_dir(&tmp)?;
        write_atomically(
            &tmp.join(PROBE_NAME),
            &records.join(PROBE_NAME),
            RECORD_MAGIC,
        )
        .and_then(|()| fs::remove_file(records.join(PROBE_NAME)))
        .map_err(|e| anyhow::anyhow!("the sign-in store {described} cannot be written: {e}"))?;
        let index = load_index(&root, &records)?;
        sync_dir(&root)
            .map_err(|e| anyhow::anyhow!("cannot flush the sign-in store {described}: {e}"))?;
        let store = Self {
            inner: Arc::new(Inner {
                root,
                records,
                tmp,
                limits,
                index: Mutex::new(index),
                write_locks: (0..WRITE_LOCKS).map(|_| Mutex::new(())).collect(),
                _lock: lock,
            }),
        };
        store.spawn_sweeper();
        Ok(store)
    }

    /// The directory, resolved.
    pub fn dir(&self) -> &Path {
        &self.inner.root
    }

    /// Records held, expired ones not yet swept included.
    pub fn len(&self) -> usize {
        self.inner.index.lock().entries.len()
    }

    /// Whether the store holds no record.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove every expired record now; the number removed.
    pub fn sweep(&self) -> usize {
        self.inner.sweep(None)
    }

    fn spawn_sweeper(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store: Weak<Inner> = Arc::downgrade(&self.inner);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let Some(inner) = store.upgrade() else {
                    break;
                };
                let swept = tokio::task::spawn_blocking(move || inner.sweep(None)).await;
                if let Err(error) = swept {
                    tracing::warn!(error = %error, "the sign-in store sweep stopped");
                }
            }
        });
    }

    async fn run<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Inner) -> Result<T, ClusterError> + Send + 'static,
    ) -> Result<T, ClusterError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || op(&inner))
            .await
            .map_err(|error| ClusterError::Internal {
                reason: format!("sign-in store task: {error}"),
            })?
    }
}

fn open_lock(root: &Path) -> anyhow::Result<File> {
    let path = root.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .map_err(|e| anyhow::anyhow!("cannot open {}: {e}", path.display()))?;
    #[cfg(unix)]
    check_owned(
        &path,
        &file
            .metadata()
            .map_err(|e| anyhow::anyhow!("cannot inspect {}: {e}", path.display()))?,
        false,
    )?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(anyhow::anyhow!(
            "the sign-in store {} is open in another gateway process; give each process a store \
             directory of its own (interactive.store.dir), or share state through a cluster \
             store",
            root.display()
        )),
        Err(fs::TryLockError::Error(e)) => {
            Err(anyhow::anyhow!("cannot lock {}: {e}", path.display()))
        }
    }
}

fn clear_dir(dir: &Path) -> anyhow::Result<()> {
    let entries =
        fs::read_dir(dir).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            fs::remove_file(&path)
                .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Read every record file into the index. Expired records are removed;
/// a file that does not decode, or is not named for the key it holds, is
/// moved to `corrupt/`.
fn load_index(root: &Path, records: &Path) -> anyhow::Result<Index> {
    let now = now_ms();
    let mut index = Index::default();
    let entries = fs::read_dir(records)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", records.display()))?;
    let mut quarantined = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        if path.extension().and_then(|e| e.to_str()) != Some(RECORD_EXTENSION) {
            continue;
        }
        let bytes =
            fs::read(&path).map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        match decode_record(&bytes) {
            Some(record) if record_name(&record.key) == name => {
                let entry = IndexEntry {
                    expires_ms: record.expires_ms,
                    size: bytes.len() as u64,
                };
                if entry.live(now) {
                    index.insert(record.key, entry);
                } else {
                    fs::remove_file(&path)
                        .map_err(|e| anyhow::anyhow!("cannot remove {}: {e}", path.display()))?;
                }
            }
            _ => {
                let corrupt = root.join(CORRUPT_DIR);
                prepare_private_dir(&corrupt)?;
                fs::rename(&path, corrupt.join(&name))
                    .map_err(|e| anyhow::anyhow!("cannot move {}: {e}", path.display()))?;
                quarantined += 1;
            }
        }
    }
    if quarantined > 0 {
        tracing::warn!(
            dir = %root.display(),
            records = quarantined,
            "damaged sign-in records moved to the store's corrupt/ directory; the sign-ins they \
             held start over"
        );
    }
    sync_dir(records).map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", records.display()))?;
    Ok(index)
}

impl Inner {
    fn write_lock(&self, name: &str) -> usize {
        usize::from_str_radix(&name[..2], 16).unwrap_or(0) % WRITE_LOCKS
    }

    fn read_record(&self, key: &str, name: &str) -> Result<Option<Record>, ClusterError> {
        let path = self.records.join(name);
        let mut bytes = Vec::new();
        match File::open(&path).and_then(|mut file| file.read_to_end(&mut bytes)) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable("read", &path, &error)),
        }
        match decode_record(&bytes) {
            Some(record) if record.key == key => Ok(Some(record)),
            _ => Err(ClusterError::Internal {
                reason: format!("sign-in store: {} is damaged", path.display()),
            }),
        }
    }

    fn write_record(
        &self,
        key: &str,
        name: &str,
        expires_ms: Option<u64>,
        value: &[u8],
    ) -> Result<(), ClusterError> {
        let bytes = encode_record(key, expires_ms, value);
        let path = self.records.join(name);
        write_atomically(&self.tmp.join(name), &path, &bytes)
            .map_err(|error| unavailable("write", &path, &error))?;
        self.index.lock().insert(
            key.to_owned(),
            IndexEntry {
                expires_ms,
                size: bytes.len() as u64,
            },
        );
        Ok(())
    }

    fn remove_record(&self, key: &str, name: &str) -> Result<bool, ClusterError> {
        let path = self.records.join(name);
        let removed = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(unavailable("remove", &path, &error)),
        };
        self.index.lock().remove(key);
        if removed {
            sync_dir(&self.records).map_err(|error| unavailable("flush", &self.records, &error))?;
        }
        Ok(removed)
    }

    /// Whether a value of `value_len` bytes may be written under `key`: a
    /// replacement always may, a new record only within the limits. The
    /// caller holds write lock `held` already.
    fn admit(&self, key: &str, value_len: usize, held: usize) -> Result<(), ClusterError> {
        let size = record_size(key, value_len);
        if value_len > self.limits.max_value_bytes {
            return Err(ClusterError::Precondition {
                reason: format!(
                    "sign-in store: a value of {value_len} bytes exceeds the {} byte limit",
                    self.limits.max_value_bytes
                ),
            });
        }
        let fits = |index: &Index| {
            index.entries.contains_key(key)
                || (index.entries.len() < self.limits.max_records
                    && index.bytes.saturating_add(size) <= self.limits.max_total_bytes)
        };
        if fits(&self.index.lock()) {
            return Ok(());
        }
        self.sweep(Some(held));
        if fits(&self.index.lock()) {
            return Ok(());
        }
        metrics::counter!("mcpg_as_state_errors_total", "op" => "full").increment(1);
        Err(ClusterError::Precondition {
            reason: format!(
                "sign-in store {} is full ({} records or {} bytes)",
                self.root.display(),
                self.limits.max_records,
                self.limits.max_total_bytes
            ),
        })
    }

    /// Remove the expired records; the number removed. `held` is the
    /// write lock the caller holds already; a record under another lock
    /// that is busy waits for the next sweep.
    fn sweep(&self, held: Option<usize>) -> usize {
        let now = now_ms();
        let expired: Vec<String> = self
            .index
            .lock()
            .entries
            .iter()
            .filter(|(_, entry)| !entry.live(now))
            .map(|(key, _)| key.clone())
            .collect();
        let mut removed = 0;
        for key in expired {
            let name = record_name(&key);
            let lock = self.write_lock(&name);
            let _guard = match held {
                Some(own) if own == lock => None,
                Some(_) => match self.write_locks[lock].try_lock() {
                    Some(guard) => Some(guard),
                    None => continue,
                },
                None => Some(self.write_locks[lock].lock()),
            };
            if self
                .index
                .lock()
                .entries
                .get(&key)
                .is_some_and(|entry| entry.live(now_ms()))
            {
                continue;
            }
            match fs::remove_file(self.records.join(&name)) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(error = %error, "a sign-in record could not be swept");
                    continue;
                }
            }
            self.index.lock().remove(&key);
        }
        if removed > 0
            && let Err(error) = sync_dir(&self.records)
        {
            tracing::warn!(error = %error, "the sign-in store could not be flushed after a sweep");
        }
        removed
    }

    fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let now = now_ms();
        if self.index.lock().live(key, now).is_none() {
            return Ok(None);
        }
        let Some(record) = self.read_record(key, &record_name(key))? else {
            return Ok(None);
        };
        if record.expires_ms.is_some_and(|at| at <= now) {
            return Ok(None);
        }
        Ok(Some(Entry {
            bytes: Bytes::from(record.value),
            expires_at: record.expires_ms.map(to_system_time),
        }))
    }

    fn put(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
        only_if_absent: bool,
    ) -> Result<bool, ClusterError> {
        let name = record_name(key);
        let lock = self.write_lock(&name);
        let _guard = self.write_locks[lock].lock();
        let now = now_ms();
        if only_if_absent && self.index.lock().live(key, now).is_some() {
            return Ok(false);
        }
        self.admit(key, value.len(), lock)?;
        self.write_record(key, &name, expiry_ms(now, ttl), value)?;
        Ok(true)
    }

    fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        let name = record_name(key);
        let _guard = self.write_locks[self.write_lock(&name)].lock();
        let live = self.index.lock().live(key, now_ms()).is_some();
        Ok(self.remove_record(key, &name)? && live)
    }

    fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let now = now_ms();
        let keys: Vec<String> = self
            .index
            .lock()
            .entries
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .filter(|(_, entry)| entry.live(now))
            .map(|(key, _)| key.clone())
            .collect();
        let mut out = Vec::new();
        for key in keys {
            if out.len() >= limit {
                break;
            }
            let record = match self.read_record(&key, &record_name(&key)) {
                Ok(Some(record)) => record,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(error = %error, "a sign-in record could not be listed");
                    continue;
                }
            };
            if record.expires_ms.is_some_and(|at| at <= now) {
                continue;
            }
            out.push((
                key,
                Entry {
                    bytes: Bytes::from(record.value),
                    expires_at: record.expires_ms.map(to_system_time),
                },
            ));
        }
        Ok(out)
    }

    fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        let name = record_name(key);
        let _guard = self.write_locks[self.write_lock(&name)].lock();
        let now = now_ms();
        if self.index.lock().live(key, now).is_none() {
            return Ok(false);
        }
        let Some(record) = self.read_record(key, &name)? else {
            self.index.lock().remove(key);
            return Ok(false);
        };
        self.write_record(key, &name, expiry_ms(now, ttl), &record.value)?;
        Ok(true)
    }

    fn incr(&self, key: &str, delta: i64, ttl: Option<Duration>) -> Result<i64, ClusterError> {
        let name = record_name(key);
        let lock = self.write_lock(&name);
        let _guard = self.write_locks[lock].lock();
        let now = now_ms();
        let live = self.index.lock().live(key, now).is_some();
        let current = if live {
            self.read_record(key, &name)?
        } else {
            None
        };
        let value = match current {
            Some(ref record) => mcpg_cluster_api::parse_counter(&record.value)?,
            None => 0,
        };
        let next = value
            .checked_add(delta)
            .ok_or_else(mcpg_cluster_api::counter_overflow)?;
        let expires_ms = match ttl {
            Some(_) => expiry_ms(now, ttl),
            None => current.and_then(|record| record.expires_ms),
        };
        let digits = next.to_string().into_bytes();
        self.admit(key, digits.len(), lock)?;
        self.write_record(key, &name, expires_ms, &digits)?;
        Ok(next)
    }
}

#[async_trait]
impl KeyValueStore for FileStore {
    async fn get(&self, key: &str) -> Result<Option<Entry>, ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.get(&key)).await
    }

    async fn put(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<(), ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.put(&key, &value, ttl, false).map(|_| ()))
            .await
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> Result<bool, ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.put(&key, &value, ttl, true))
            .await
    }

    async fn delete(&self, key: &str) -> Result<bool, ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.delete(&key)).await
    }

    async fn list_prefix(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, Entry)>, ClusterError> {
        let prefix = prefix.to_owned();
        self.run(move |inner| inner.list_prefix(&prefix, limit))
            .await
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> Result<bool, ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.expire(&key, ttl)).await
    }

    async fn incr(
        &self,
        key: &str,
        delta: i64,
        ttl: Option<Duration>,
    ) -> Result<i64, ClusterError> {
        let key = key.to_owned();
        self.run(move |inner| inner.incr(&key, delta, ttl)).await
    }
}

/// A state key read from its file, or generated into it.
pub struct KeyFile {
    pub key: Zeroizing<[u8; STATE_KEY_BYTES]>,
    /// Whether this call created the file.
    pub generated: bool,
}

/// Read the state key at `path`, or generate one there when the file is
/// absent. The file holds the key in URL-safe base64, is created with mode
/// 0600 on unix, and is restricted to that mode when found more open; on
/// unix a key file that is a symbolic link or another user's is refused.
/// Call it only with the store lock held: nothing else then creates the
/// file. Neither the key nor the file's contents appear in an error.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<KeyFile> {
    use base64::Engine as _;
    use chacha20poly1305::aead::Generate as _;
    let described = path.display();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(mut file) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let meta = file.metadata().map_err(|e| {
                    anyhow::anyhow!("cannot inspect the state key file {described}: {e}")
                })?;
                check_owned(path, &meta, false)?;
                if meta.permissions().mode() & 0o077 != 0 {
                    file.set_permissions(fs::Permissions::from_mode(0o600))
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "the state key file {described} is readable by other users and \
                                 cannot be restricted ({e}); run `chmod 600 {described}`"
                            )
                        })?;
                    tracing::warn!(
                        path = %described,
                        "the state key file was readable by other users; restricted it to mode 0600"
                    );
                }
            }
            let mut contents = Zeroizing::new(String::with_capacity(256));
            file.read_to_string(&mut contents)
                .map_err(|e| anyhow::anyhow!("cannot read the state key file {described}: {e}"))?;
            let decoded = Zeroizing::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(contents.trim().trim_end_matches('='))
                    .unwrap_or_default(),
            );
            if decoded.len() != STATE_KEY_BYTES {
                anyhow::bail!(
                    "the state key file {described} does not hold a {STATE_KEY_BYTES}-byte \
                     URL-safe base64 key; restore it from a backup (the stored sign-ins cannot \
                     be opened without it), or remove it together with the store's records/ \
                     directory to start over"
                );
            }
            let mut key = Zeroizing::new([0u8; STATE_KEY_BYTES]);
            key.copy_from_slice(&decoded);
            Ok(KeyFile {
                key,
                generated: false,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = Zeroizing::new(<[u8; STATE_KEY_BYTES]>::try_generate().map_err(|e| {
                anyhow::anyhow!("the operating system's random number generator failed: {e}")
            })?);
            let mut encoded = Zeroizing::new(String::with_capacity(2 * STATE_KEY_BYTES));
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode_string(key.as_slice(), &mut encoded);
            encoded.push('\n');
            let tmp = path.with_extension("key.tmp");
            write_atomically(&tmp, path, encoded.as_bytes())
                .map_err(|e| anyhow::anyhow!("cannot write the state key file {described}: {e}"))?;
            Ok(KeyFile {
                key,
                generated: true,
            })
        }
        #[cfg(unix)]
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(anyhow::anyhow!(
            "the state key file {described} is a symbolic link; replace it with the key file \
             itself"
        )),
        Err(error) => Err(anyhow::anyhow!(
            "cannot read the state key file {described}: {error}"
        )),
    }
}

#[cfg(test)]
#[path = "authorization_server_file_store_tests.rs"]
mod tests;
