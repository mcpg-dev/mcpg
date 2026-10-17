use std::sync::atomic::Ordering;

use super::*;
use crate::builtins::cluster_primitives::MemoryKv;
use crate::config::AppConfig;
use crate::runtime::events::log::{LogEntry, RowBody};
use crate::runtime::events::occurrence::StoredOccurrence;
use crate::runtime::events::test_support::{
    SESSION_KEY, ScriptedWatch, eventually, eventually_async, keys,
};

const NOW: u64 = 1_000_000;
const WATCH_URI: &str = "mcpg-event://orders.created";

fn config(types: &str) -> AppConfig {
    let yaml = format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    resources:
      - name: report
        description: The nightly report.
        uri: "file:///data/report.csv"
        backend: {{ kind: mock, response: "x" }}
        watch: {{ strategy: {{ type: poll, interval_ms: 10000 }} }}
    events:
{types}
"#
    );
    AppConfig::load_from_yaml_str(&yaml).unwrap()
}

const WATCH_TYPE: &str = r#"      - name: orders.created
        source:
          watch:
            strategy: { type: nats_topic, subject: orders }"#;

struct Fixture {
    plugin: Arc<ScriptedWatch>,
    catalog: EventCatalog,
    log: Arc<EventLog>,
    lease: watch::Sender<Option<WriterLease>>,
    ctx: SourceContext,
    /// What the sources metered.
    usage: crate::runtime::cp_metrics::TestRecorder,
}

async fn fixture(types: &str, fetcher: Option<ResourceFetcher>) -> Fixture {
    fixture_with(ScriptedWatch::new("nats_topic"), types, fetcher).await
}

async fn fixture_with(
    plugin: Arc<ScriptedWatch>,
    types: &str,
    fetcher: Option<ResourceFetcher>,
) -> Fixture {
    let registry = ScriptedWatch::registry(&[Arc::clone(&plugin)]);
    let catalog = EventCatalog::build(&config(types), &keys(), &registry)
        .await
        .unwrap();
    let log = Arc::new(EventLog::new(Arc::new(MemoryKv::new()), None, keys()));
    let lease = watch::channel(Some(WriterLease {
        fence: 1,
        expires_at_ms: u64::MAX,
    }))
    .0;
    let usage = crate::runtime::cp_metrics::TestRecorder::default();
    let ctx = SourceContext {
        log: Arc::clone(&log),
        lease: lease.subscribe(),
        registry,
        fetcher,
        max_payload_bytes: 245_760,
        inbox: None,
        core: std::sync::Weak::new(),
        usage: crate::runtime::cp_metrics::ToolCallRecorderHandle::new(Arc::new(usage.clone())),
        quota: crate::runtime::cp_quota::QuotaStatusHandle::default(),
    };
    Fixture {
        plugin,
        catalog,
        log,
        lease,
        ctx,
        usage,
    }
}

async fn head_of(log: &EventLog, sk: &str) -> u64 {
    log.head(sk).await.unwrap().map_or(0, |h| h.seq)
}

async fn wait_for_head(log: &EventLog, sk: &str, seq: u64) {
    for _ in 0..200 {
        if head_of(log, sk).await >= seq {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("log head never reached {seq}");
}

#[tokio::test]
async fn a_watch_source_runs_only_while_there_is_demand() {
    let f = fixture(WATCH_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();

    manager.reconcile(&f.catalog, &|_| false, &f.ctx, 1, 1_000, NOW);
    assert!(manager.running().is_empty());

    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert_eq!(manager.running(), ["orders.created"]);
    assert!(eventually(|| f.plugin.uris() == [WATCH_URI]).await);

    f.plugin.fire(WATCH_URI).await;
    f.plugin.fire(WATCH_URI).await;
    wait_for_head(&f.log, &sk, 2).await;
    let rows = f.log.read(&sk, 0, 10).await.unwrap();
    for row in &rows {
        let LogEntry::Row(row) = row else {
            panic!("readable");
        };
        let RowBody::Event(occurrence) = &row.body else {
            panic!("an event");
        };
        assert!(occurrence.data["observedAt"].is_string());
        assert_eq!(occurrence.data.as_object().unwrap().len(), 1);
        assert_eq!(
            uuid::Uuid::parse_str(&occurrence.event_id)
                .unwrap()
                .get_version_num(),
            7
        );
    }

    // Demand ends: the source lingers, then stops.
    manager.reconcile(&f.catalog, &|_| false, &f.ctx, 1, 1_000, NOW + 500);
    assert_eq!(manager.running(), ["orders.created"]);
    manager.reconcile(&f.catalog, &|_| false, &f.ctx, 1, 1_000, NOW + 1_501);
    assert!(manager.running().is_empty());
    assert!(eventually(|| f.plugin.cancelled.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test]
async fn an_always_on_source_runs_without_demand() {
    let f = fixture(
        &WATCH_TYPE.replace(
            "        source:",
            "        always_on: true\n        source:",
        ),
        None,
    )
    .await;
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| false, &f.ctx, 1, 0, NOW);
    manager.reconcile(&f.catalog, &|_| false, &f.ctx, 1, 0, NOW + 10_000_000);
    assert_eq!(manager.running(), ["orders.created"]);
}

#[tokio::test]
async fn a_restart_on_a_log_with_rows_marks_the_gap_first() {
    let f = fixture(WATCH_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 1).await);
    f.plugin.fire(WATCH_URI).await;
    wait_for_head(&f.log, &sk, 1).await;
    assert_eq!(f.log.head(&sk).await.unwrap().unwrap().last_gap_seq, 0);

    // A new plugin registry (a reload) restarts the source.
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 2, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 2).await);
    assert!(eventually(|| f.plugin.cancelled.load(Ordering::SeqCst) == 1).await);
    wait_for_head(&f.log, &sk, 2).await;
    let head = f.log.head(&sk).await.unwrap().unwrap();
    assert_eq!(head.last_gap_seq, 2);
    assert!(matches!(
        f.log.get(&sk, 2).await.unwrap(),
        Some(LogEntry::Row(row)) if matches!(row.body, RowBody::Gap { .. })
    ));

    // An unchanged generation and definition keeps the running source.
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 2, 1_000, NOW);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(f.plugin.started.load(Ordering::SeqCst), 2);
}

const PAYLOAD_TYPE: &str = r#"      - name: orders.created
        source:
          watch:
            strategy: { type: nats_topic, subject: orders }
            event_type: nats.message"#;

fn declared(resume: bool, placement: mcpg_plugin_protocol::EventPlacement) -> Arc<ScriptedWatch> {
    ScriptedWatch::declaring(mcpg_plugin_protocol::WatchStrategyDescriptor {
        kind: "nats_topic".to_owned(),
        placement,
        resume,
        event_types: vec![mcpg_plugin_protocol::EventTypeDescriptor {
            name: "nats.message".to_owned(),
            description: String::new(),
            input_schema: None,
            payload_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "string" } },
            })),
        }],
    })
}

fn message(id: &str, cursor: Option<u64>) -> WatchEvent {
    WatchEvent {
        event_id: Some(format!("m-{id}")),
        event_type: Some("nats.message".to_owned()),
        occurred_at: Some("2024-04-05T19:34:38.123Z".to_owned()),
        data: Some(serde_json::json!({ "id": id })),
        upstream_cursor: cursor.map(|c| serde_json::json!({ "pos": c })),
        ..WatchEvent::default()
    }
}

async fn occurrences(log: &EventLog, sk: &str) -> Vec<StoredOccurrence> {
    log.read(sk, 0, 100)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|entry| match entry {
            LogEntry::Row(row) => match row.body {
                RowBody::Event(occurrence) => Some(occurrence),
                RowBody::Gap { .. } | RowBody::Ended { .. } => None,
            },
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_payload_source_appends_the_plugins_events_of_its_type() {
    let f = fixture_with(declared(false, Default::default()), PAYLOAD_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.uris() == [WATCH_URI]).await);

    f.plugin.emit(WATCH_URI, message("o-1", None)).await;
    let other = WatchEvent {
        event_type: Some("nats.other".to_owned()),
        ..message("o-2", None)
    };
    f.plugin.emit(WATCH_URI, other).await;
    let off_schema = WatchEvent {
        data: Some(serde_json::json!({ "id": 7 })),
        ..message("o-3", None)
    };
    f.plugin.emit(WATCH_URI, off_schema).await;
    f.plugin.emit(WATCH_URI, message("o-4", None)).await;
    wait_for_head(&f.log, &sk, 2).await;

    let stored = occurrences(&f.log, &sk).await;
    let ids: Vec<&str> = stored.iter().map(|o| o.event_id.as_str()).collect();
    assert_eq!(
        ids,
        ["m-o-1", "m-o-4"],
        "another type and an off-schema payload are dropped"
    );
    assert_eq!(stored[0].data, serde_json::json!({ "id": "o-1" }));
    assert_eq!(stored[0].timestamp, "2024-04-05T19:34:38.123Z");

    f.plugin.emit(WATCH_URI, message("o-1", None)).await;
    f.plugin.emit(WATCH_URI, message("o-5", None)).await;
    wait_for_head(&f.log, &sk, 3).await;
    assert_eq!(
        f.usage.ingested("orders.created"),
        3,
        "each appended occurrence once: not a dropped one, not a repeated id"
    );
    assert!(
        f.usage
            .event_usage()
            .iter()
            .all(|call| call.mode == "watch" && call.bytes > 0 && call.delivered == 0),
        "{:?}",
        f.usage.event_usage()
    );
}

#[tokio::test]
async fn the_plugin_hears_of_each_event_the_source_is_done_with() {
    let f = fixture_with(declared(false, Default::default()), PAYLOAD_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.uris() == [WATCH_URI]).await);
    let acked = || f.plugin.acknowledged.lock().clone();

    // Stored, a repeat of a stored id, another type, a payload the type
    // refuses: each is done with, in order.
    f.plugin.emit(WATCH_URI, message("o-1", Some(1))).await;
    f.plugin.emit(WATCH_URI, message("o-1", Some(2))).await;
    let other = WatchEvent {
        event_type: Some("nats.other".to_owned()),
        ..message("o-2", Some(3))
    };
    f.plugin.emit(WATCH_URI, other).await;
    let refused = WatchEvent {
        data: Some(serde_json::json!({ "id": 7 })),
        ..message("o-3", Some(4))
    };
    f.plugin.emit(WATCH_URI, refused).await;
    f.plugin.emit(WATCH_URI, message("o-4", None)).await;
    wait_for_head(&f.log, &sk, 2).await;
    let want: Vec<serde_json::Value> = (1..=4)
        .map(|pos| serde_json::json!({ "pos": pos }))
        .collect();
    assert!(eventually(|| acked().len() == 4).await, "{:?}", acked());
    assert_eq!(
        acked(),
        want,
        "in emit order; an event with no position needs no answer"
    );

    // An event the source may want again is not acknowledged, so the
    // upstream redelivers it: here, the replica is no longer the owner.
    f.lease.send_replace(None);
    f.plugin.emit(WATCH_URI, message("o-5", Some(5))).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(acked().len(), 4, "{:?}", acked());

    manager.stop_all();
    assert!(eventually(|| f.plugin.cancelled.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test]
async fn a_gap_the_plugin_reports_is_marked_in_the_log() {
    let f = fixture_with(declared(true, Default::default()), PAYLOAD_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.uris() == [WATCH_URI]).await);
    // A gap alone, then an event that also says events before it are gone.
    f.plugin
        .emit(
            WATCH_URI,
            WatchEvent {
                gap: true,
                upstream_cursor: Some(serde_json::json!({ "pos": 1 })),
                ..WatchEvent::default()
            },
        )
        .await;
    f.plugin
        .emit(
            WATCH_URI,
            WatchEvent {
                gap: true,
                ..message("o-1", Some(2))
            },
        )
        .await;
    wait_for_head(&f.log, &sk, 3).await;
    let rows = f.log.read(&sk, 0, 10).await.unwrap();
    let kinds: Vec<&str> = rows
        .iter()
        .map(|entry| match entry {
            LogEntry::Row(row) => match &row.body {
                RowBody::Gap { reason, .. } => {
                    assert_eq!(*reason, GapReason::UpstreamTruncated);
                    "gap"
                }
                RowBody::Event(_) => "event",
                RowBody::Ended { .. } => "ended",
            },
            _ => "other",
        })
        .collect();
    assert_eq!(kinds, ["gap", "gap", "event"]);
    assert!(
        eventually(|| f.plugin.acknowledged.lock().clone()
            == [
                serde_json::json!({ "pos": 1 }),
                serde_json::json!({ "pos": 2 })
            ])
        .await,
        "a gap alone is done with too"
    );
    manager.stop_all();
}

#[tokio::test]
async fn a_resource_source_acknowledges_a_payload_free_change_once_stored() {
    let f = fixture(WATCH_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.uris() == [WATCH_URI]).await);
    let change = WatchEvent {
        upstream_cursor: Some(serde_json::json!({ "receipt": "r-1" })),
        ..WatchEvent::default()
    };
    f.plugin.emit(WATCH_URI, change).await;
    wait_for_head(&f.log, &sk, 1).await;
    assert!(
        eventually(
            || f.plugin.acknowledged.lock().clone() == [serde_json::json!({ "receipt": "r-1" })]
        )
        .await
    );
    manager.stop_all();
}

#[tokio::test]
async fn a_resumable_source_restarts_where_it_stopped_without_a_gap() {
    let f = fixture_with(declared(true, Default::default()), PAYLOAD_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 1).await);
    assert!(
        f.plugin.specs.lock()[0]
            .get(mcpg_plugin_protocol::WATCH_RESUME_SPEC_KEY)
            .is_none(),
        "nothing to resume from yet"
    );
    f.plugin.emit(WATCH_URI, message("o-1", Some(41))).await;
    wait_for_head(&f.log, &sk, 1).await;
    assert!(
        eventually_async(|| async {
            f.log.resume_position(&sk, None).await.unwrap()
                == Some(serde_json::json!({ "pos": 41 }))
        })
        .await
    );

    // A reload restarts the source: it resumes, and marks no gap.
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 2, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 2).await);
    assert_eq!(
        f.plugin.specs.lock()[1][mcpg_plugin_protocol::WATCH_RESUME_SPEC_KEY],
        serde_json::json!({ "pos": 41 })
    );
    f.plugin.emit(WATCH_URI, message("o-2", Some(42))).await;
    wait_for_head(&f.log, &sk, 2).await;
    let head = f.log.head(&sk).await.unwrap().unwrap();
    assert_eq!(head.last_gap_seq, 0, "a resumed source leaves no hole");
    assert_eq!(occurrences(&f.log, &sk).await.len(), 2);
}

#[tokio::test]
async fn an_every_replica_source_writes_the_inbox_not_the_log() {
    let mut f = fixture_with(
        declared(false, mcpg_plugin_protocol::EventPlacement::EveryReplica),
        PAYLOAD_TYPE,
        None,
    )
    .await;
    let ty = f.catalog.get("orders.created").unwrap();
    assert!(!ty.source.needs_runner(), "the owner does not run it");
    assert!(ty.source.runs_on_every_replica());
    let sk = ty.source_key.clone();
    f.ctx.inbox = Some(InboxLimits {
        ttl: Duration::from_secs(60),
        max_rows: 100,
    });
    // No owner lease on this replica: the inbox is how the event gets there.
    f.lease.send_replace(None);
    let mut manager = SourceManager::default();
    manager.reconcile_selected(
        &f.catalog,
        SourceSpec::runs_on_every_replica,
        &|_| true,
        &f.ctx,
        1,
        1_000,
        NOW,
    );
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 1).await);
    f.plugin.emit(WATCH_URI, message("o-1", None)).await;
    assert!(eventually_async(|| async { f.log.inbox_pending(&sk).await.unwrap() == 1 }).await);
    assert_eq!(head_of(&f.log, &sk).await, 0);
}

#[tokio::test]
async fn a_removed_type_stops_its_source() {
    let f = fixture(WATCH_TYPE, None).await;
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 1).await);
    manager.reconcile(&EventCatalog::empty(), &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(manager.running().is_empty());
    assert!(eventually(|| f.plugin.cancelled.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test]
async fn changes_without_the_owner_lease_are_dropped() {
    let f = fixture(WATCH_TYPE, None).await;
    let sk = f.catalog.get("orders.created").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(eventually(|| f.plugin.started.load(Ordering::SeqCst) == 1).await);
    f.lease.send_replace(None);
    f.plugin.fire(WATCH_URI).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(head_of(&f.log, &sk).await, 0);
}

#[tokio::test]
async fn inbound_types_need_no_runner() {
    let f = fixture(
        "      - name: gh\n        source: { inbound: { source_id: gh, allow_unsigned: true } }",
        None,
    )
    .await;
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    assert!(manager.running().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_polled_resource_reports_each_change_after_the_first_read() {
    let reads = Arc::new(parking_lot::Mutex::new(vec![
        "v1".to_owned(),
        "v1".to_owned(),
        "v2".to_owned(),
        "v2".to_owned(),
        "v3".to_owned(),
    ]));
    let calls = Arc::clone(&reads);
    let fetcher: ResourceFetcher = Arc::new(move |uri: &str| {
        assert_eq!(uri, "file:///data/report.csv");
        let mut reads = calls.lock();
        (!reads.is_empty()).then(|| reads.remove(0))
    });
    let f = fixture(
        "      - name: report.changed\n        source:\n          resource: file:///data/report.csv",
        Some(fetcher),
    )
    .await;
    let sk = f.catalog.get("report.changed").unwrap().source_key.clone();
    let mut manager = SourceManager::default();
    manager.reconcile(&f.catalog, &|_| true, &f.ctx, 1, 1_000, NOW);
    tokio::time::sleep(Duration::from_secs(45)).await;
    assert!(reads.lock().is_empty(), "five reads, ten seconds apart");
    assert_eq!(head_of(&f.log, &sk).await, 2, "v1→v2 and v2→v3");
    let LogEntry::Row(row) = f.log.get(&sk, 1).await.unwrap().unwrap() else {
        panic!("readable");
    };
    let RowBody::Event(occurrence) = row.body else {
        panic!("an event");
    };
    assert_eq!(occurrence.data["uri"], "file:///data/report.csv");
    manager.stop_all();
}
