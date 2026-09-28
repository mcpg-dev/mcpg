use super::*;

fn open(dir: &Path) -> FileStore {
    FileStore::open(dir, FileStoreLimits::default()).expect("the store opens")
}

fn record_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir.join(RECORDS_DIR))
        .expect("records/ exists")
        .flatten()
        .map(|entry| entry.path())
        .collect()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_store_keeps_the_key_value_contract() {
    let dirs = std::sync::Mutex::new(Vec::new());
    // Every write is flushed to disk, which on a busy disk takes longer
    // than the millisecond timing leaves between two calls.
    mcpg_cluster_api::test_suite::run_kv_contract_with(
        mcpg_cluster_api::test_suite::KvContractTiming::seconds_granularity(),
        || async {
            let dir = tempfile::tempdir().expect("tempdir");
            let store = open(dir.path());
            dirs.lock().expect("dirs").push(dir);
            Arc::new(store) as Arc<dyn KeyValueStore>
        },
    )
    .await;
}

#[tokio::test]
async fn records_survive_a_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = open(dir.path());
        store
            .put("as/v1/grant/a", Bytes::from_static(b"one"), None)
            .await
            .expect("put");
        store
            .put(
                "as/v1/grant/b",
                Bytes::from_static(b"two"),
                Some(Duration::from_secs(600)),
            )
            .await
            .expect("put");
        assert!(
            store
                .put_if_absent("as/v1/claim", Bytes::from_static(b"1"), None)
                .await
                .expect("claim")
        );
    }
    let store = open(dir.path());
    assert_eq!(store.len(), 3, "the index is rebuilt from the files");
    let one = store
        .get("as/v1/grant/a")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(&one.bytes[..], b"one");
    assert!(one.expires_at.is_none());
    let two = store
        .get("as/v1/grant/b")
        .await
        .expect("get")
        .expect("kept");
    assert_eq!(&two.bytes[..], b"two");
    assert!(two.expires_at.is_some(), "the expiry is kept");
    assert!(
        !store
            .put_if_absent("as/v1/claim", Bytes::from_static(b"2"), None)
            .await
            .expect("claim"),
        "a claim made before the restart still holds"
    );
    let mut listed: Vec<String> = store
        .list_prefix("as/v1/grant/", 10)
        .await
        .expect("list")
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    listed.sort();
    assert_eq!(listed, ["as/v1/grant/a", "as/v1/grant/b"]);
}

#[tokio::test]
async fn one_process_at_a_time_opens_a_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = open(dir.path());
    let refused =
        FileStore::open(dir.path(), FileStoreLimits::default()).expect_err("the store is locked");
    assert!(
        refused
            .to_string()
            .contains("open in another gateway process"),
        "{refused}"
    );
    drop(first);
    open(dir.path());
}

#[tokio::test]
async fn a_store_that_cannot_be_created_refuses_to_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("not-a-directory");
    fs::write(&file, b"x").expect("write");
    let refused = FileStore::open(&file.join("oauth"), FileStoreLimits::default())
        .expect_err("a file blocks the directory");
    assert!(
        refused
            .to_string()
            .contains("cannot create the sign-in store"),
        "{refused}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn files_are_private_to_the_gateway_user() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("oauth");
    let store = open(&root);
    store
        .put("as/v1/grant/a", Bytes::from_static(b"one"), None)
        .await
        .expect("put");
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join(RECORDS_DIR)), 0o700);
    assert_eq!(mode(&root.join(TMP_DIR)), 0o700);
    assert_eq!(mode(&root.join(LOCK_FILE)), 0o600);
    for record in record_files(&root) {
        assert_eq!(mode(&record), 0o600, "{}", record.display());
    }
}

/// A store directory found open to other users is restricted to its owner
/// at open, the root included.
#[cfg(unix)]
#[tokio::test]
async fn an_open_store_directory_is_restricted_to_its_owner() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("oauth");
    for sub in [root.clone(), root.join(RECORDS_DIR), root.join(TMP_DIR)] {
        fs::create_dir_all(&sub).expect("mkdir");
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o777)).expect("chmod");
    }
    let _store = open(&root);
    for sub in [root.clone(), root.join(RECORDS_DIR), root.join(TMP_DIR)] {
        assert_eq!(mode(&sub), 0o700, "{}", sub.display());
    }
}

/// An entry of the store that is a symbolic link is refused rather than
/// followed: it would put the records, or the lock, where someone else
/// chose.
#[cfg(unix)]
#[tokio::test]
async fn a_store_entry_that_is_a_symbolic_link_is_refused() {
    let elsewhere = tempfile::tempdir().expect("tempdir");
    for entry in [RECORDS_DIR, LOCK_FILE] {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("oauth");
        fs::create_dir(&root).expect("mkdir");
        let target = elsewhere.path().join(entry);
        if entry == RECORDS_DIR {
            fs::create_dir(&target).expect("mkdir");
        } else {
            fs::write(&target, b"").expect("write");
        }
        std::os::unix::fs::symlink(&target, root.join(entry)).expect("symlink");
        let refused = FileStore::open(&root, FileStoreLimits::default())
            .expect_err("a symbolic link is refused");
        let message = format!("{refused:#}");
        assert!(message.contains("symbolic link"), "{entry}: {message}");
    }
}

/// A store directory another user owns is refused: its owner could read
/// the records, or replace the state key they are sealed with.
#[cfg(unix)]
#[tokio::test]
async fn a_store_directory_another_user_owns_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("oauth");
    fs::create_dir(&root).expect("mkdir");
    let other = effective_uid().wrapping_add(1);
    if std::os::unix::fs::chown(&root, Some(other), None).is_err() {
        // Only a privileged test run can hand a directory to another user.
        return;
    }
    let refused =
        FileStore::open(&root, FileStoreLimits::default()).expect_err("another user's directory");
    let message = format!("{refused:#}");
    assert!(
        message.contains(&format!("belongs to uid {other}")),
        "{message}"
    );
}

#[tokio::test]
async fn a_record_file_is_named_by_a_hash_of_its_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    store
        .put("as/v1/../../escape", Bytes::from_static(b"v"), None)
        .await
        .expect("put");
    let files = record_files(dir.path());
    assert_eq!(files.len(), 1);
    let name = files[0].file_name().and_then(|n| n.to_str()).expect("name");
    assert_eq!(name, record_name("as/v1/../../escape"));
    assert!(!name.contains("escape"));
    assert_eq!(name.len(), 64 + 1 + RECORD_EXTENSION.len());
}

#[tokio::test]
async fn leftovers_of_a_crash_are_cleared_and_damage_is_set_aside() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = open(dir.path());
        store
            .put("as/v1/grant/a", Bytes::from_static(b"one"), None)
            .await
            .expect("put");
        store
            .put("as/v1/grant/b", Bytes::from_static(b"two"), None)
            .await
            .expect("put");
    }
    fs::write(dir.path().join(TMP_DIR).join("half-written.rec"), b"MCPG").expect("tmp");
    let damaged = dir
        .path()
        .join(RECORDS_DIR)
        .join(record_name("as/v1/grant/b"));
    let mut bytes = fs::read(&damaged).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&damaged, bytes).expect("damage");

    let store = open(dir.path());
    assert_eq!(
        fs::read_dir(dir.path().join(TMP_DIR)).expect("tmp").count(),
        0,
        "writes in progress at a crash are discarded"
    );
    assert!(store.get("as/v1/grant/a").await.expect("get").is_some());
    assert!(store.get("as/v1/grant/b").await.expect("get").is_none());
    assert!(
        dir.path()
            .join(CORRUPT_DIR)
            .join(record_name("as/v1/grant/b"))
            .exists(),
        "the damaged record is kept aside, not deleted"
    );
}

#[tokio::test]
async fn a_record_renamed_to_another_key_is_set_aside() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = open(dir.path());
        store
            .put("as/v1/grant/a", Bytes::from_static(b"one"), None)
            .await
            .expect("put");
    }
    let records = dir.path().join(RECORDS_DIR);
    fs::rename(
        records.join(record_name("as/v1/grant/a")),
        records.join(record_name("as/v1/grant/z")),
    )
    .expect("rename");
    let store = open(dir.path());
    assert!(store.is_empty());
    assert!(store.get("as/v1/grant/z").await.expect("get").is_none());
}

#[tokio::test]
async fn expired_records_are_removed_at_open_and_by_the_sweep() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let store = open(dir.path());
        store
            .put(
                "as/v1/old",
                Bytes::from_static(b"x"),
                Some(Duration::from_millis(20)),
            )
            .await
            .expect("put");
    }
    std::thread::sleep(Duration::from_millis(40));
    let store = open(dir.path());
    assert!(store.is_empty(), "an expired record is dropped at open");
    assert!(record_files(dir.path()).is_empty());

    store
        .put(
            "as/v1/short",
            Bytes::from_static(b"x"),
            Some(Duration::from_millis(20)),
        )
        .await
        .expect("put");
    store
        .put("as/v1/long", Bytes::from_static(b"y"), None)
        .await
        .expect("put");
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(store.sweep(), 1);
    assert_eq!(store.len(), 1);
    assert_eq!(record_files(dir.path()).len(), 1);
}

#[tokio::test]
async fn the_store_refuses_new_records_beyond_its_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let limits = FileStoreLimits {
        max_records: 2,
        max_value_bytes: 16,
        max_total_bytes: u64::MAX,
    };
    let store = FileStore::open(dir.path(), limits).expect("opens");
    store
        .put("as/v1/a", Bytes::from_static(b"1"), None)
        .await
        .expect("put");
    store
        .put(
            "as/v1/b",
            Bytes::from_static(b"2"),
            Some(Duration::from_secs(1)),
        )
        .await
        .expect("put");
    let full = store
        .put("as/v1/c", Bytes::from_static(b"3"), None)
        .await
        .expect_err("a third record is refused");
    assert!(matches!(full, ClusterError::Precondition { .. }), "{full}");
    store
        .put("as/v1/a", Bytes::from_static(b"replaced"), None)
        .await
        .expect("a replacement is always admitted");
    let too_large = store
        .put("as/v1/a", Bytes::from(vec![0u8; 17]), None)
        .await
        .expect_err("a value over the limit is refused");
    assert!(matches!(too_large, ClusterError::Precondition { .. }));

    std::thread::sleep(Duration::from_millis(1_100));
    store
        .put("as/v1/c", Bytes::from_static(b"3"), None)
        .await
        .expect("an expired record makes room");
    assert_eq!(store.len(), 2);
}

#[tokio::test]
async fn the_byte_limit_counts_every_record_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let limits = FileStoreLimits {
        max_records: 100,
        max_value_bytes: 1024,
        max_total_bytes: record_size("as/v1/a", 100) + record_size("as/v1/b", 100),
    };
    let store = FileStore::open(dir.path(), limits).expect("opens");
    for key in ["as/v1/a", "as/v1/b"] {
        store
            .put(key, Bytes::from(vec![7u8; 100]), None)
            .await
            .expect("fits");
    }
    store
        .put("as/v1/c", Bytes::from(vec![7u8; 1]), None)
        .await
        .expect_err("the byte budget is spent");
    store.delete("as/v1/a").await.expect("delete");
    store
        .put("as/v1/c", Bytes::from(vec![7u8; 1]), None)
        .await
        .expect("a deletion frees its bytes");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_of_many_concurrent_claims_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open(dir.path());
    let mut claims = Vec::new();
    for n in 0..16u8 {
        let store = store.clone();
        claims.push(tokio::spawn(async move {
            store
                .put_if_absent("as/v1/code_used/x", Bytes::from(vec![n]), None)
                .await
                .expect("claim")
        }));
    }
    let mut winners = 0;
    for claim in claims {
        winners += usize::from(claim.await.expect("task"));
    }
    assert_eq!(winners, 1);
}

#[test]
fn a_record_decodes_only_whole_and_unaltered() {
    let bytes = encode_record("as/v1/k", Some(42), b"value");
    let record = decode_record(&bytes).expect("decodes");
    assert_eq!(record.key, "as/v1/k");
    assert_eq!(record.expires_ms, Some(42));
    assert_eq!(record.value, b"value");
    assert_eq!(bytes.len() as u64, record_size("as/v1/k", 5));
    for cut in 0..bytes.len() {
        assert!(decode_record(&bytes[..cut]).is_none(), "cut at {cut}");
    }
    for at in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 1;
        assert!(decode_record(&flipped).is_none(), "flip at {at}");
    }
}

#[test]
fn a_state_key_is_generated_once_and_read_after() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.key");
    let first = load_or_generate_key(&path).expect("generates");
    assert!(first.generated);
    let contents = fs::read_to_string(&path).expect("written");
    assert_eq!(
        contents.len(),
        43 + 1,
        "URL-safe base64 of 32 bytes and a newline"
    );
    #[cfg(unix)]
    assert_eq!(mode(&path), 0o600);
    let second = load_or_generate_key(&path).expect("reads");
    assert!(!second.generated);
    assert_eq!(*first.key, *second.key);
    assert!(!path.with_extension("key.tmp").exists());
}

#[test]
fn a_damaged_state_key_is_refused_without_its_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.key");
    fs::write(&path, "c2hvcnQtYnV0LXNlY3JldA\n").expect("write");
    let refused = load_or_generate_key(&path)
        .err()
        .expect("a short key is refused");
    let message = refused.to_string();
    assert!(message.contains("does not hold a 32-byte"), "{message}");
    assert!(!message.contains("c2hvcnQtYnV0LXNlY3JldA"), "{message}");
    assert_eq!(
        fs::read_to_string(&path).expect("kept"),
        "c2hvcnQtYnV0LXNlY3JldA\n",
        "a damaged key file is never replaced"
    );
}

#[cfg(unix)]
#[test]
fn a_state_key_open_to_others_is_restricted() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.key");
    let generated = load_or_generate_key(&path).expect("generates");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
    let read = load_or_generate_key(&path).expect("reads");
    assert_eq!(*generated.key, *read.key);
    assert_eq!(mode(&path), 0o600);
}

/// A state key file that is a symbolic link, or another user's, is
/// refused: whoever controls it knows the key every record is sealed with.
#[cfg(unix)]
#[test]
fn a_state_key_that_is_a_link_or_another_users_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let planted = dir.path().join("planted.key");
    load_or_generate_key(&planted).expect("generates");
    let path = dir.path().join("state.key");
    std::os::unix::fs::symlink(&planted, &path).expect("symlink");
    let refused = load_or_generate_key(&path)
        .err()
        .expect("a symbolic link is refused");
    assert!(
        refused.to_string().contains("is a symbolic link"),
        "{refused}"
    );

    fs::remove_file(&path).expect("unlink");
    fs::copy(&planted, &path).expect("copy");
    let other = effective_uid().wrapping_add(1);
    if std::os::unix::fs::chown(&path, Some(other), None).is_err() {
        // Only a privileged test run can hand a file to another user.
        return;
    }
    let refused = load_or_generate_key(&path)
        .err()
        .expect("another user's key file is refused");
    assert!(
        refused
            .to_string()
            .contains(&format!("belongs to uid {other}")),
        "{refused}"
    );
}
