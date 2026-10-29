use super::*;
use crate::builtins::cluster_primitives::MemoryKv;
use crate::runtime::events::cursor::CursorScope;
use crate::runtime::events::test_support::keys;
use serde_json::json;

const SK: &str = "sk_test";

fn store() -> Arc<MemoryKv> {
    Arc::new(MemoryKv::new())
}

fn log_over(kv: &Arc<MemoryKv>) -> EventLog {
    EventLog::new(Arc::clone(kv) as Arc<dyn KeyValueStore>, None, keys())
}

fn lease(fence: u64) -> WriterLease {
    WriterLease {
        fence,
        expires_at_ms: now_ms() + 60_000,
    }
}

fn retention() -> EventRetentionConfig {
    EventRetentionConfig::default()
}

fn occ(id: &str) -> StoredOccurrence {
    StoredOccurrence {
        event_id: id.to_owned(),
        timestamp: "2026-10-03T12:00:00.000Z".to_owned(),
        data: json!({ "id": id }),
        audience: None,
        arguments: None,
    }
}

fn seqs(entries: &[LogEntry]) -> Vec<u64> {
    entries.iter().map(LogEntry::seq).collect()
}

fn scope() -> CursorScope {
    CursorScope::new(SK, &json!({}))
}

#[tokio::test]
async fn an_empty_log_has_head_zero_floor_one_and_a_stable_epoch() {
    let log = log_over(&store());
    let bounds = log.bounds(SK).await.unwrap();
    assert_eq!((bounds.head, bounds.floor), (0, 1));
    assert_ne!(bounds.epoch, 0);
    assert_eq!(log.bounds(SK).await.unwrap().epoch, bounds.epoch);
    assert_ne!(log.bounds("sk_other").await.unwrap().epoch, bounds.epoch);
    assert!(log.read(SK, 0, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn appends_take_consecutive_sequence_numbers_from_one() {
    let log = log_over(&store());
    let mut appended_bytes = 0;
    for (i, id) in ["a", "b", "c"].into_iter().enumerate() {
        let AppendOutcome::Appended { seq, bytes } = log
            .append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap()
        else {
            panic!("appended");
        };
        assert_eq!(seq, i as u64 + 1);
        appended_bytes += bytes;
    }
    let head = log.head(SK).await.unwrap().unwrap();
    assert_eq!(head.seq, 3);
    assert_eq!(head.fence, 1);
    assert!(head.bytes > 0);
    assert_eq!(
        head.bytes, appended_bytes,
        "each append names its row's size"
    );
    let rows = log.read(SK, 0, 10).await.unwrap();
    assert_eq!(seqs(&rows), vec![1, 2, 3]);
    let LogEntry::Row(first) = &rows[0] else {
        panic!("readable");
    };
    assert_eq!(first.body, RowBody::Event(occ("a")));
    assert_eq!(seqs(&log.read(SK, 1, 1).await.unwrap()), vec![2]);
    assert!(log.read(SK, 3, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_repeated_event_id_is_appended_once() {
    let log = log_over(&store());
    log.append(SK, occ("a"), &retention(), lease(1))
        .await
        .unwrap();
    assert_eq!(
        log.append(SK, occ("a"), &retention(), lease(1))
            .await
            .unwrap(),
        AppendOutcome::Duplicate
    );
    assert_eq!(log.head(SK).await.unwrap().unwrap().seq, 1);
    // The same id in another log is another event.
    assert_eq!(
        log.append("sk_other", occ("a"), &retention(), lease(1))
            .await
            .unwrap()
            .seq(),
        Some(1)
    );
}

#[tokio::test]
async fn the_writer_announces_each_new_head() {
    let log = log_over(&store());
    let mut head = log.watch_head(SK);
    log.append(SK, occ("a"), &retention(), lease(1))
        .await
        .unwrap();
    head.changed().await.unwrap();
    assert_eq!(*head.borrow(), 1);
}

#[tokio::test]
async fn every_value_carries_the_format_version() {
    let kv = store();
    let log = log_over(&kv);
    log.append(SK, occ("a"), &retention(), lease(1))
        .await
        .unwrap();
    for key in [format!("ev:head:{SK}"), format!("ev:log:{SK}:{:020}", 1)] {
        let entry = kv.get(&key).await.unwrap().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&entry.bytes).unwrap();
        assert_eq!(value["v"], 1, "{key}");
    }
    log.bounds(SK).await.unwrap();
    let epoch = kv.get(&format!("ev:epoch:{SK}")).await.unwrap().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&epoch.bytes).unwrap();
    assert_eq!(value["v"], 1);
}

#[tokio::test]
async fn a_row_or_head_of_a_newer_format_is_never_misread() {
    let kv = store();
    let log = log_over(&kv);
    log.append(SK, occ("a"), &retention(), lease(1))
        .await
        .unwrap();
    let key = format!("ev:log:{SK}:{:020}", 1);
    kv.put(&key, Bytes::from(r#"{"v":2,"seq":1,"shape":"new"}"#), None)
        .await
        .unwrap();
    // Another process: the writer reads its own rows from memory.
    let reader = log_over(&kv);
    assert_eq!(
        reader.read(SK, 0, 10).await.unwrap(),
        vec![LogEntry::Unreadable { seq: 1 }]
    );
    kv.put(
        &format!("ev:head:{SK}"),
        Bytes::from(r#"{"v":2,"seq":9}"#),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        log.append(SK, occ("b"), &retention(), lease(1)).await,
        Err(LogError::NewerFormat)
    ));
    assert!(matches!(log.head(SK).await, Err(LogError::NewerFormat)));
}

/// A store that counts the log rows it serves, each after a millisecond, so
/// that concurrent readers overlap.
#[derive(Debug, Default)]
struct RowReadCountingKv {
    inner: MemoryKv,
    row_gets: std::sync::atomic::AtomicUsize,
}

type KvResult<T> = Result<T, ClusterError>;

#[async_trait::async_trait]
impl KeyValueStore for RowReadCountingKv {
    async fn get(&self, key: &str) -> KvResult<Option<mcpg_cluster_api::Entry>> {
        if key.starts_with("ev:log:") {
            self.row_gets
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.inner.get(key).await
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Option<Duration>) -> KvResult<()> {
        self.inner.put(key, value, ttl).await
    }

    async fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Option<Duration>,
    ) -> KvResult<bool> {
        self.inner.put_if_absent(key, value, ttl).await
    }

    async fn delete(&self, key: &str) -> KvResult<bool> {
        self.inner.delete(key).await
    }

    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> KvResult<mcpg_cluster_api::KvPage> {
        self.inner.list_page(prefix, cursor, limit).await
    }

    async fn expire(&self, key: &str, ttl: Option<Duration>) -> KvResult<bool> {
        self.inner.expire(key, ttl).await
    }

    async fn incr(&self, key: &str, delta: i64, ttl: Option<Duration>) -> KvResult<i64> {
        self.inner.incr(key, delta, ttl).await
    }
}

#[tokio::test]
async fn the_streams_a_head_wakes_together_read_each_row_from_the_store_once() {
    let kv = Arc::new(RowReadCountingKv::default());
    let store: Arc<dyn KeyValueStore> = kv.clone();
    let writer = EventLog::new(Arc::clone(&store), None, keys());
    for n in 0..10 {
        writer
            .append(SK, occ(&format!("e{n}")), &retention(), lease(1))
            .await
            .unwrap();
    }
    // Another process, whose memory holds none of the rows.
    let reader = EventLog::new(store, None, keys());
    let before = kv.row_gets.load(std::sync::atomic::Ordering::SeqCst);
    let reads = futures::future::join_all((0..16).map(|_| reader.read_rows(SK, 1, 10))).await;
    for rows in reads {
        assert_eq!(seqs(&rows.unwrap()), (1..=10).collect::<Vec<u64>>());
    }
    assert_eq!(
        kv.row_gets.load(std::sync::atomic::Ordering::SeqCst) - before,
        10,
        "16 readers of the same rows read each from the store once"
    );
}

#[tokio::test]
async fn a_lost_log_is_never_read_from_memory() {
    let kv = store();
    let reader = log_over(&kv);
    let writer = log_over(&kv);
    for id in ["a", "b"] {
        writer
            .append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    let before = reader.bounds(SK).await.unwrap();
    assert_eq!(seqs(&reader.read_rows(SK, 1, 2).await.unwrap()), vec![1, 2]);
    for key in [
        format!("ev:head:{SK}"),
        format!("ev:epoch:{SK}"),
        format!("ev:log:{SK}:{:020}", 1),
        format!("ev:log:{SK}:{:020}", 2),
    ] {
        kv.delete(&key).await.unwrap();
    }
    log_over(&kv)
        .append(SK, occ("x"), &retention(), lease(2))
        .await
        .unwrap();
    assert_ne!(reader.bounds(SK).await.unwrap().epoch, before.epoch);
    let rows = reader.read_rows(SK, 1, 2).await.unwrap();
    assert!(
        matches!(&rows[..], [LogEntry::Row(row)] if matches!(&row.body, RowBody::Event(o) if o.event_id == "x")),
        "{rows:?}"
    );
}

#[tokio::test]
async fn a_newer_fence_deposes_the_writer_until_its_lease_ends() {
    let log = log_over(&store());
    log.append(SK, occ("a"), &retention(), lease(5))
        .await
        .unwrap();
    assert!(matches!(
        log.append(SK, occ("b"), &retention(), lease(3)).await,
        Err(LogError::Deposed)
    ));
    assert!(matches!(
        log.enforce_retention(SK, &retention(), lease(3)).await,
        Err(LogError::Deposed)
    ));
    // A coordinator restart can hand out a lower fence; once the recorded
    // lease has ended the new owner takes over.
    let short_end = now_ms() + 1_000;
    let short = WriterLease {
        fence: 5,
        expires_at_ms: short_end,
    };
    log.append(SK, occ("a2"), &retention(), short)
        .await
        .unwrap();
    while now_ms() <= short_end {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        log.append(SK, occ("b"), &retention(), lease(3))
            .await
            .unwrap()
            .seq(),
        Some(3)
    );
    assert_eq!(log.head(SK).await.unwrap().unwrap().fence, 3);
    // A newer fence always writes.
    assert_eq!(
        log.append(SK, occ("c"), &retention(), lease(9))
            .await
            .unwrap()
            .seq(),
        Some(4)
    );
}

#[tokio::test]
async fn an_expired_lease_never_writes() {
    let log = log_over(&store());
    let expired = WriterLease {
        fence: 1,
        expires_at_ms: now_ms().saturating_sub(1),
    };
    assert!(matches!(
        log.append(SK, occ("a"), &retention(), expired).await,
        Err(LogError::LeaseExpired)
    ));
    assert!(matches!(
        log.append_gap(
            SK,
            GapReason::SourceRestart,
            RowScope::default(),
            &retention(),
            expired
        )
        .await,
        Err(LogError::LeaseExpired)
    ));
    assert!(log.head(SK).await.unwrap().is_none());
}

#[tokio::test]
async fn a_slot_taken_by_a_crashed_writer_is_adopted_not_overwritten() {
    let kv = store();
    let log = log_over(&kv);
    log.append(SK, occ("a"), &retention(), lease(1))
        .await
        .unwrap();
    // A writer wrote row 2 and stopped before moving the head.
    let orphan = LogRow {
        v: FORMAT_VERSION,
        seq: 2,
        appended_at_ms: now_ms(),
        bytes: 10,
        body: RowBody::Event(occ("orphan")),
    };
    kv.put(
        &format!("ev:log:{SK}:{:020}", 2),
        Bytes::from(serde_json::to_vec(&orphan).unwrap()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        log.append(SK, occ("b"), &retention(), lease(1))
            .await
            .unwrap()
            .seq(),
        Some(3)
    );
    let rows = log.read(SK, 0, 10).await.unwrap();
    assert_eq!(seqs(&rows), vec![1, 2, 3]);
    assert_eq!(rows[1], LogEntry::Row(orphan));
}

#[tokio::test]
async fn retention_evicts_the_oldest_rows_by_count() {
    let log = log_over(&store());
    for id in ["a", "b", "c", "d", "e"] {
        log.append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    let bounded = EventRetentionConfig {
        max_events: 3,
        ..retention()
    };
    let report = log.enforce_retention(SK, &bounded, lease(1)).await.unwrap();
    assert_eq!(
        report,
        RetentionReport {
            evicted: 2,
            floor: 3
        }
    );
    assert_eq!(seqs(&log.read(SK, 0, 10).await.unwrap()), vec![3, 4, 5]);
    assert!(log.get(SK, 1).await.unwrap().is_none());
    let bounds = log.bounds(SK).await.unwrap();
    assert_eq!((bounds.floor, bounds.head), (3, 5));
    // Already within bounds: nothing more.
    assert_eq!(
        log.enforce_retention(SK, &bounded, lease(1))
            .await
            .unwrap()
            .evicted,
        0
    );
}

#[tokio::test]
async fn retention_evicts_by_bytes_and_by_age() {
    let log = log_over(&store());
    for id in ["a", "b", "c", "d"] {
        log.append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    let LogEntry::Row(row) = log.get(SK, 1).await.unwrap().unwrap() else {
        panic!("readable");
    };
    let by_bytes = EventRetentionConfig {
        max_bytes: Some(row.bytes * 2),
        ..retention()
    };
    log.enforce_retention(SK, &by_bytes, lease(1))
        .await
        .unwrap();
    assert_eq!(seqs(&log.read(SK, 0, 10).await.unwrap()), vec![3, 4]);
    assert!(log.head(SK).await.unwrap().unwrap().bytes <= row.bytes * 2);

    tokio::time::sleep(Duration::from_millis(5)).await;
    let by_age = EventRetentionConfig {
        max_age_ms: 1,
        ..retention()
    };
    let report = log.enforce_retention(SK, &by_age, lease(1)).await.unwrap();
    assert_eq!(report.floor, 5);
    assert!(log.read(SK, 0, 10).await.unwrap().is_empty());
    let head = log.head(SK).await.unwrap().unwrap();
    assert_eq!((head.seq, head.bytes), (4, 0));
    // Sequence numbers keep counting after the log empties.
    assert_eq!(
        log.append(SK, occ("e"), &retention(), lease(1))
            .await
            .unwrap()
            .seq(),
        Some(5)
    );
}

#[tokio::test]
async fn resume_starts_after_a_valid_cursor_and_reports_gaps() {
    let log = log_over(&store());
    for id in ["a", "b", "c"] {
        log.append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    let epoch = log.epoch(SK).await.unwrap();
    let at_two = log.seal_cursor(epoch, 0, 2, &scope());
    let resumed = log
        .resume(SK, Some(&at_two), &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed,
        ResumePoint {
            epoch,
            after_seq: 2,
            truncated: false
        }
    );

    let from_now = log
        .resume(SK, None, &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((from_now.after_seq, from_now.truncated), (3, false));

    let garbage = log
        .resume(SK, Some("ev1.nope"), &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((garbage.after_seq, garbage.truncated), (3, true));

    // A gap marker after the cursor means events may be missing.
    log.append_gap(
        SK,
        GapReason::SourceRestart,
        RowScope::default(),
        &retention(),
        lease(1),
    )
    .await
    .unwrap();
    let across_gap = log
        .resume(SK, Some(&at_two), &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((across_gap.after_seq, across_gap.truncated), (2, true));
    let after_gap = log.seal_cursor(epoch, 0, 4, &scope());
    let past = log
        .resume(SK, Some(&after_gap), &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((past.after_seq, past.truncated), (4, false));
    assert_eq!(log.head(SK).await.unwrap().unwrap().last_gap_seq, 4);
    assert!(matches!(
        log.get(SK, 4).await.unwrap(),
        Some(LogEntry::Row(LogRow {
            body: RowBody::Gap {
                reason: GapReason::SourceRestart,
                scope: _,
            },
            ..
        }))
    ));

    // A cursor of an older schema epoch asks the client to re-list.
    let old_schema = log.seal_cursor(epoch, 0, 2, &scope());
    assert_eq!(
        log.resume(SK, Some(&old_schema), &scope(), 1, None)
            .await
            .unwrap(),
        Err(SchemaChanged)
    );
}

#[tokio::test]
async fn a_cursor_below_the_floor_resumes_at_the_head_truncated() {
    let log = log_over(&store());
    for id in ["a", "b", "c", "d"] {
        log.append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    let epoch = log.epoch(SK).await.unwrap();
    let at_one = log.seal_cursor(epoch, 0, 1, &scope());
    let bounded = EventRetentionConfig {
        max_events: 2,
        ..retention()
    };
    log.enforce_retention(SK, &bounded, lease(1)).await.unwrap();
    let resumed = log
        .resume(SK, Some(&at_one), &scope(), 0, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((resumed.after_seq, resumed.truncated), (4, true));
}

#[tokio::test]
async fn max_age_moves_the_start_forward_and_reports_it() {
    let log = log_over(&store());
    for id in ["old1", "old2"] {
        log.append(SK, occ(id), &retention(), lease(1))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    log.append(SK, occ("new"), &retention(), lease(1))
        .await
        .unwrap();
    let epoch = log.epoch(SK).await.unwrap();
    let at_zero = log.seal_cursor(epoch, 0, 0, &scope());
    // Wide margins on both sides, so a slow machine cannot move a row
    // across the cutoff.
    let resumed = log
        .resume(SK, Some(&at_zero), &scope(), 0, Some(600))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((resumed.after_seq, resumed.truncated), (2, true));
    let wide = log
        .resume(SK, Some(&at_zero), &scope(), 0, Some(60_000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((wide.after_seq, wide.truncated), (0, false));
}

fn inbox_row(id: &str) -> InboxRow {
    InboxRow {
        v: FORMAT_VERSION,
        event_id: Some(id.to_owned()),
        timestamp: None,
        data: json!({ "id": id }),
        received_at_ms: now_ms(),
        ..InboxRow::default()
    }
}

const LIMITS: InboxLimits = InboxLimits {
    ttl: Duration::from_secs(3_600),
    max_rows: 100,
};

async fn identity_shape(row: InboxRow) -> Option<StoredOccurrence> {
    Some(StoredOccurrence {
        event_id: row.event_id.unwrap_or_default(),
        timestamp: "2026-10-03T12:00:00.000Z".to_owned(),
        data: row.data,
        audience: row.audience,
        arguments: None,
    })
}

/// One drain pass over the inbox of `SK` with `shape`, and what it did.
async fn drain<F, Fut>(log: &EventLog, lease: WriterLease, shape: F) -> Result<InboxDrain, LogError>
where
    F: Fn(InboxRow) -> Fut,
    Fut: std::future::Future<Output = Option<StoredOccurrence>>,
{
    let mut pass = InboxDrain::default();
    log.drain_inbox(SK, &retention(), lease, shape, &mut pass)
        .await
        .map(|()| pass)
}

#[tokio::test]
async fn inbox_rows_drain_into_the_log_in_arrival_order() {
    let kv = store();
    let log = log_over(&kv);
    for id in ["x", "y", "z"] {
        assert_eq!(
            log.inbox_put(SK, inbox_row(id), LIMITS).await.unwrap(),
            InboxOutcome::Accepted
        );
    }
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 3);
    let drained = drain(&log, lease(1), identity_shape).await.unwrap();
    assert_eq!((drained.consumed, drained.appended), (3, 3));
    assert_eq!(
        drained.bytes,
        log.head(SK).await.unwrap().unwrap().bytes,
        "the pass names the bytes it appended"
    );
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 0);
    let ids: Vec<String> = log
        .read(SK, 0, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|e| match e {
            LogEntry::Row(LogRow {
                body: RowBody::Event(o),
                ..
            }) => o.event_id,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(ids, ["x", "y", "z"]);
    assert!(
        kv.get(&format!("ev:in:{SK}:{:020}", 1))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        drain(&log, lease(1), identity_shape).await.unwrap(),
        InboxDrain::default()
    );
}

/// Under cluster state encryption every value is sealed except counters,
/// which the backend adds to in place; the inbox must read its counter in a
/// way the encrypting store allows.
#[tokio::test]
async fn the_inbox_works_over_an_encrypted_store() {
    let cipher = Arc::new(
        mcpg_plugin_host::credential_cache_cipher::EventCipher::from_raw_key(
            &[3u8; 32],
            "k1".into(),
        )
        .unwrap(),
    );
    let sealed: Arc<dyn KeyValueStore> = Arc::new(
        mcpg_plugin_host::cluster_encryption::EncryptingKeyValueStore::new(
            Arc::clone(&store()) as Arc<dyn KeyValueStore>,
            cipher,
        ),
    );
    let log = EventLog::new(sealed, None, keys());
    for id in ["x", "y", "z"] {
        assert_eq!(
            log.inbox_put(SK, inbox_row(id), LIMITS).await.unwrap(),
            InboxOutcome::Accepted
        );
    }
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 3);
    assert_eq!(
        drain(&log, lease(1), identity_shape)
            .await
            .unwrap()
            .appended,
        3
    );
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 0);
    assert_eq!(log.read(SK, 0, 10).await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_redelivered_inbox_event_is_appended_once() {
    let log = log_over(&store());
    log.inbox_put(SK, inbox_row("same"), LIMITS).await.unwrap();
    log.inbox_put(SK, inbox_row("same"), LIMITS).await.unwrap();
    drain(&log, lease(1), identity_shape).await.unwrap();
    assert_eq!(seqs(&log.read(SK, 0, 10).await.unwrap()), vec![1]);
}

#[tokio::test]
async fn a_dropped_row_is_consumed_without_an_append() {
    let log = log_over(&store());
    log.inbox_put(SK, inbox_row("bad"), LIMITS).await.unwrap();
    let pass = drain(&log, lease(1), |_| async { None }).await.unwrap();
    assert_eq!((pass.consumed, pass.appended, pass.bytes), (1, 0, 0));
    assert!(log.head(SK).await.unwrap().is_none());
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 0);
}

#[tokio::test]
async fn a_full_inbox_refuses_with_a_retry_after() {
    let log = log_over(&store());
    let tight = InboxLimits {
        ttl: Duration::from_secs(3_600),
        max_rows: 2,
    };
    log.inbox_put(SK, inbox_row("a"), tight).await.unwrap();
    log.inbox_put(SK, inbox_row("b"), tight).await.unwrap();
    assert!(matches!(
        log.inbox_put(SK, inbox_row("c"), tight).await.unwrap(),
        InboxOutcome::Full { .. }
    ));
    drain(&log, lease(1), identity_shape).await.unwrap();
    assert_eq!(
        log.inbox_put(SK, inbox_row("c"), tight).await.unwrap(),
        InboxOutcome::Accepted
    );
}

#[tokio::test]
async fn an_inbox_nobody_drains_refuses_once_its_ttl_passes() {
    let log = log_over(&store());
    let short = InboxLimits {
        ttl: Duration::from_millis(20),
        max_rows: 100,
    };
    assert_eq!(
        log.inbox_put(SK, inbox_row("a"), short).await.unwrap(),
        InboxOutcome::Accepted
    );
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(matches!(
        log.inbox_put(SK, inbox_row("b"), short).await.unwrap(),
        InboxOutcome::Full { .. }
    ));
}

#[tokio::test]
async fn a_reserved_slot_not_yet_written_holds_the_drain_back() {
    let kv = store();
    let log = log_over(&kv);
    log.inbox_put(SK, inbox_row("a"), LIMITS).await.unwrap();
    // A writer took slot 2 and has not written it yet.
    kv.incr(&format!("ev:in:n:{SK}"), 1, None).await.unwrap();
    log.inbox_put(SK, inbox_row("c"), LIMITS).await.unwrap();
    let consumed = drain(&log, lease(1), identity_shape)
        .await
        .unwrap()
        .consumed;
    assert_eq!(consumed, 1, "stops at the reserved slot within its grace");
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 2);
    // The writer finishes; the drain continues in order.
    kv.put(
        &format!("ev:in:{SK}:{:020}", 2),
        Bytes::from(serde_json::to_vec(&inbox_row("b")).unwrap()),
        None,
    )
    .await
    .unwrap();
    drain(&log, lease(1), identity_shape).await.unwrap();
    assert_eq!(seqs(&log.read(SK, 0, 10).await.unwrap()), vec![1, 2, 3]);
}

#[tokio::test]
async fn a_deposed_writer_stops_draining_without_losing_rows() {
    let log = log_over(&store());
    log.append(SK, occ("a"), &retention(), lease(9))
        .await
        .unwrap();
    log.inbox_put(SK, inbox_row("b"), LIMITS).await.unwrap();
    assert!(matches!(
        drain(&log, lease(3), identity_shape).await,
        Err(LogError::Deposed)
    ));
    assert_eq!(log.inbox_pending(SK).await.unwrap(), 1);
}

#[tokio::test]
async fn a_breaking_schema_change_moves_the_epoch_and_an_additive_one_does_not() {
    let kv = store();
    let log = log_over(&kv);
    let input = json!({ "type": "object" });
    let payload = json!({ "type": "object", "properties": { "id": { "type": "string" } } });
    assert_eq!(
        log.schema_epoch("orders", &input, &payload).await.unwrap(),
        0
    );
    assert_eq!(
        log.schema_epoch("orders", &input, &payload).await.unwrap(),
        0
    );

    let grown = json!({
        "type": "object",
        "properties": { "id": { "type": "string" }, "region": { "type": "string" } },
    });
    assert_eq!(log.schema_epoch("orders", &input, &grown).await.unwrap(), 0);

    let broken = json!({ "type": "object", "properties": { "id": { "type": "integer" } } });
    assert_eq!(
        log.schema_epoch("orders", &input, &broken).await.unwrap(),
        1
    );
    // A replica still on an older config gets the epoch that config had.
    assert_eq!(
        log.schema_epoch("orders", &input, &payload).await.unwrap(),
        0
    );
    // Another log over the same store agrees.
    assert_eq!(
        log_over(&kv)
            .schema_epoch("orders", &input, &broken)
            .await
            .unwrap(),
        1
    );
    assert_eq!(log.schema_epoch("other", &input, &broken).await.unwrap(), 0);
}

#[tokio::test]
async fn the_resume_position_is_the_last_one_stored() {
    let log = log_over(&store());
    assert_eq!(log.resume_position(SK, None).await.unwrap(), None);
    log.store_resume_position(SK, None, json!({ "pos": 1 }), None)
        .await
        .unwrap();
    log.store_resume_position(SK, None, json!({ "pos": 2 }), None)
        .await
        .unwrap();
    assert_eq!(
        log.resume_position(SK, None).await.unwrap(),
        Some(json!({ "pos": 2 }))
    );
    log.store_resume_position(SK, Some("a"), json!("7"), None)
        .await
        .unwrap();
    assert_eq!(
        log.resume_position(SK, Some("a")).await.unwrap(),
        Some(json!("7"))
    );
    assert_eq!(
        log.resume_position(SK, None).await.unwrap(),
        Some(json!({ "pos": 2 })),
        "each slot keeps its own position"
    );
}

#[tokio::test]
async fn one_event_id_is_kept_once_for_each_set_of_arguments() {
    let log = log_over(&store());
    let tagged = |arguments: &str| StoredOccurrence {
        arguments: Some(arguments.to_owned()),
        ..occ("a")
    };
    assert!(matches!(
        log.append(SK, tagged("eu"), &retention(), lease(1)).await,
        Ok(AppendOutcome::Appended { seq: 1, .. })
    ));
    assert!(matches!(
        log.append(SK, tagged("us"), &retention(), lease(1)).await,
        Ok(AppendOutcome::Appended { seq: 2, .. })
    ));
    assert!(matches!(
        log.append(SK, tagged("eu"), &retention(), lease(1)).await,
        Ok(AppendOutcome::Duplicate)
    ));
    assert!(matches!(
        log.append(SK, occ("a"), &retention(), lease(1)).await,
        Ok(AppendOutcome::Appended { seq: 3, .. })
    ));
    assert!(matches!(
        log.append(SK, occ("a"), &retention(), lease(1)).await,
        Ok(AppendOutcome::Duplicate)
    ));
}
