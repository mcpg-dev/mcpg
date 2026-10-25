//! A fleet of watch engines in one process. The replicas share one
//! subscription store, one coordinator's lock table and one bus, as the
//! replicas of a deployment share a coordinator; each records what it fans
//! out, so a test counts what every subscriber in the fleet is told.
//!
//! Time is paused: a sleep runs the collectors' passes at once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcpg_cluster_api::{ClusterBackend, KeyValueStore, PubSub};

use super::pipeline_store::DeliveryMessage;
use super::subscription_store::{
    KvBackedSubscriptionStore, SubscriberIdentity, SubscriptionStore, WatchState,
};
use super::subscriptions::{SubscriptionLease, SubscriptionService};
use super::watch_engine::{
    COLLECT_INTERVAL, MAINTAIN_TICK, SessionLiveness, WatchCluster, WatchConfig, WatchEngine,
    WatchStrategy,
};
use super::watch_shards::{WATCH_SHARDS, shard_of};
use crate::builtins::cluster_primitives::{MemoryBus, MemoryKv};
use crate::builtins::cluster_single_node::SingleNodeClusterBackend;

/// The interval of every poll watcher: the engine's floor.
const POLL: Duration = Duration::from_secs(10);

struct Fleet {
    kv: Arc<MemoryKv>,
    backend: Arc<dyn ClusterBackend>,
    bus: Arc<dyn PubSub>,
    /// The body each URI reads as.
    content: Arc<Mutex<HashMap<String, String>>>,
    configs: HashMap<String, WatchConfig>,
}

struct Replica {
    engine: WatchEngine,
    service: Arc<SubscriptionService>,
    /// `(session, uri)` of every notification this replica fanned out.
    told: Arc<Mutex<Vec<(String, String)>>>,
}

impl Fleet {
    fn new(uris: &[&str]) -> Self {
        let configs = uris
            .iter()
            .map(|uri| {
                (
                    (*uri).to_owned(),
                    WatchConfig {
                        uri: (*uri).to_owned(),
                        strategy: WatchStrategy::Poll {
                            interval_ms: POLL.as_millis() as u64,
                        },
                        notification_filter: None,
                        compiled_filter_program: None,
                    },
                )
            })
            .collect();
        Self {
            kv: Arc::new(MemoryKv::new()),
            backend: SingleNodeClusterBackend::with_node_id("coordinator"),
            bus: Arc::new(MemoryBus::new()),
            content: Arc::default(),
            configs,
        }
    }

    fn set(&self, uri: &str, body: &str) {
        self.content
            .lock()
            .unwrap()
            .insert(uri.to_owned(), body.to_owned());
    }

    fn state(&self) -> WatchState {
        WatchState::new(Arc::clone(&self.kv) as Arc<dyn KeyValueStore>)
    }

    fn store(&self) -> KvBackedSubscriptionStore {
        KvBackedSubscriptionStore::new(Arc::clone(&self.kv) as Arc<dyn KeyValueStore>, 100)
    }

    async fn replica(&self) -> Replica {
        self.replica_with(None).await
    }

    async fn replica_with(&self, session_alive: Option<SessionLiveness>) -> Replica {
        let store: Arc<dyn SubscriptionStore> = Arc::new(self.store());
        let told = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&told);
        let publish = Arc::new(move |session: &str, message: DeliveryMessage| {
            let uri = message.jsonrpc_message["params"]["uri"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            sink.lock().unwrap().push((session.to_owned(), uri));
        });
        let content = Arc::clone(&self.content);
        let fetch = Arc::new(move |uri: &str| content.lock().unwrap().get(uri).cloned());
        let engine = WatchEngine::start(self.configs.clone(), Arc::clone(&store), publish, fetch);
        let service = SubscriptionService::new(store, engine.clone());
        engine
            .attach_cluster(WatchCluster {
                backend: Some(Arc::clone(&self.backend)),
                bus: Some(Arc::clone(&self.bus)),
                tenant_segment: None,
                session_alive,
            })
            .await;
        Replica {
            engine,
            service,
            told,
        }
    }
}

impl Replica {
    async fn subscribe(&self, session: &str, uri: &str) -> SubscriptionLease {
        self.service
            .acquire(session, uri, identity(session))
            .await
            .expect("the store takes the subscription")
    }

    async fn owns(&self, uri: &str) -> bool {
        self.engine.owned_shards().await.contains(&shard_of(uri))
    }

    async fn running(&self) -> usize {
        self.engine.active_watch_count().await
    }
}

fn identity(session: &str) -> Option<SubscriberIdentity> {
    Some(SubscriberIdentity {
        session_id: session.to_owned(),
        ..Default::default()
    })
}

/// Notifications of `uri` the fleet fanned out to `session`.
fn told(fleet: &[&Replica], session: &str, uri: &str) -> usize {
    fleet
        .iter()
        .map(|replica| {
            replica
                .told
                .lock()
                .unwrap()
                .iter()
                .filter(|(s, u)| s == session && u == uri)
                .count()
        })
        .sum()
}

/// Let every collector run `n` passes.
async fn passes(n: u32) {
    tokio::time::sleep(MAINTAIN_TICK * n + Duration::from_millis(1)).await;
}

/// Let the work that commands already sent spawned run, with no time
/// passing.
async fn drain() {
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }
}

/// The two replicas, the one that holds `uri`'s shard first.
async fn by_holder<'a>(a: &'a Replica, b: &'a Replica, uri: &str) -> (&'a Replica, &'a Replica) {
    if a.owns(uri).await { (a, b) } else { (b, a) }
}

/// Two replicas whose sessions subscribe to one URI run one watcher between
/// them, and each subscriber is told of a change once.
#[tokio::test(start_paused = true)]
async fn a_uri_subscribed_on_two_replicas_has_one_watcher() {
    let uri = "res://shared";
    let fleet = Fleet::new(&[uri]);
    fleet.set(uri, "v1");
    let a = fleet.replica().await;
    let b = fleet.replica().await;
    passes(4).await;

    let a_shards = a.engine.owned_shards().await;
    let b_shards = b.engine.owned_shards().await;
    assert_eq!(
        a_shards.len() + b_shards.len(),
        WATCH_SHARDS as usize,
        "every shard has a holder"
    );
    assert!(
        !a_shards.is_empty() && !b_shards.is_empty(),
        "the replicas share the shards"
    );
    assert!(
        a_shards.iter().all(|shard| !b_shards.contains(shard)),
        "no shard has two holders"
    );

    let _on_a = a.subscribe("session-a", uri).await;
    let _on_b = b.subscribe("session-b", uri).await;
    drain().await;
    assert_eq!(
        a.running().await + b.running().await,
        1,
        "one watcher in the fleet"
    );
    // The listing tells every replica of both subscriptions.
    passes(1).await;
    assert_eq!(
        a.running().await + b.running().await,
        1,
        "still one watcher once every replica has listed the demand"
    );
    let (holder, _) = by_holder(&a, &b, uri).await;
    assert_eq!(holder.running().await, 1, "the shard holder runs it");

    // The first poll takes the baseline; the change after it fires.
    tokio::time::sleep(POLL + Duration::from_secs(1)).await;
    fleet.set(uri, "v2");
    tokio::time::sleep(POLL + Duration::from_secs(1)).await;
    assert_eq!(told(&[&a, &b], "session-a", uri), 1);
    assert_eq!(told(&[&a, &b], "session-b", uri), 1);
}

/// The shard holder starts the watcher of a URI subscribed on another
/// replica as soon as the nudge arrives, and stops it when the last
/// subscriber anywhere leaves.
#[tokio::test(start_paused = true)]
async fn a_subscriber_on_another_replica_moves_the_holders_watcher_at_once() {
    let uri = "res://remote";
    let fleet = Fleet::new(&[uri]);
    let a = fleet.replica().await;
    let b = fleet.replica().await;
    passes(4).await;
    let (holder, other) = by_holder(&a, &b, uri).await;

    let lease = other.subscribe("session-x", uri).await;
    // No time passes: only the nudge can tell the holder.
    drain().await;
    assert_eq!(holder.running().await, 1, "the nudge starts the watcher");
    assert_eq!(
        other.running().await,
        0,
        "a replica without the shard runs none"
    );

    drop(lease);
    drain().await;
    assert_eq!(
        holder.running().await,
        0,
        "the last subscriber leaving stops the watcher"
    );
    assert!(!fleet.state().has_demand(uri).await.unwrap());
}

/// A replica that stops hands its shards to the others at once, and the
/// next holder tells of a change made while the shard moved.
#[tokio::test(start_paused = true)]
async fn a_stopping_replica_hands_its_watchers_over() {
    let uri = "res://handover";
    let fleet = Fleet::new(&[uri]);
    fleet.set(uri, "v1");
    let a = fleet.replica().await;
    let b = fleet.replica().await;
    passes(4).await;
    let (holder, survivor) = by_holder(&a, &b, uri).await;

    let _held = survivor.subscribe("session-s", uri).await;
    drain().await;
    assert_eq!(holder.running().await, 1);
    // The holder's first poll leaves the baseline in the store.
    tokio::time::sleep(POLL + Duration::from_secs(1)).await;
    assert!(fleet.state().baseline(uri).await.unwrap().is_some());

    holder.service.shutdown().await;
    fleet.set(uri, "v2");
    passes(2).await;
    assert_eq!(
        survivor.engine.owned_shards().await.len(),
        WATCH_SHARDS as usize,
        "the survivor holds every shard"
    );
    assert_eq!(survivor.running().await, 1, "and runs the watcher");

    tokio::time::sleep(POLL + Duration::from_secs(1)).await;
    assert_eq!(
        told(&[&a, &b], "session-s", uri),
        1,
        "the change made during the handover is told once"
    );
}

/// The row of a stream whose replica left the fleet goes; a live
/// replica's row on the same URI stays, and so does the watcher.
#[tokio::test(start_paused = true)]
async fn rows_a_departed_replica_held_are_removed() {
    let uri = "res://departed";
    let fleet = Fleet::new(&[uri]);
    let a = fleet.replica().await;
    passes(1).await;

    let _live = a.subscribe("session-live", uri).await;
    fleet
        .store()
        .subscribe_held(
            "session-dead",
            uri,
            identity("session-dead"),
            "departed-member",
        )
        .unwrap();

    // The first sweep finds the row gone, the second removes it.
    tokio::time::sleep(COLLECT_INTERVAL * 2 + MAINTAIN_TICK * 2).await;
    assert_eq!(fleet.store().subscribers_for(uri), vec!["session-live"]);
    assert_eq!(a.running().await, 1);
}

/// A URI whose every row belonged to a departed replica loses its demand
/// marker, and its watcher stops.
#[tokio::test(start_paused = true)]
async fn a_uri_left_without_live_rows_stops_its_watcher() {
    let uri = "res://orphaned";
    let fleet = Fleet::new(&[uri]);
    let a = fleet.replica().await;
    passes(1).await;

    fleet
        .store()
        .subscribe_held(
            "session-dead",
            uri,
            identity("session-dead"),
            "departed-member",
        )
        .unwrap();
    passes(1).await;
    assert_eq!(a.running().await, 1, "the row's demand starts the watcher");

    tokio::time::sleep(COLLECT_INTERVAL * 2 + MAINTAIN_TICK * 2).await;
    assert!(fleet.store().subscribers_for(uri).is_empty());
    assert!(!fleet.state().has_demand(uri).await.unwrap());
    assert_eq!(a.running().await, 0);
}

/// A row a session holds goes once the session store says the session
/// ended; a live session's row and one whose session the store cannot
/// answer for stay.
#[tokio::test(start_paused = true)]
async fn rows_of_sessions_that_ended_are_removed() {
    let uri = "res://legacy";
    let fleet = Fleet::new(&[uri]);
    let alive: SessionLiveness = Arc::new(|session: &str| match session {
        "session-live" => Some(true),
        "session-ended" => Some(false),
        _ => None,
    });
    let _a = fleet.replica_with(Some(alive)).await;
    passes(1).await;

    let store = fleet.store();
    for session in ["session-live", "session-ended", "session-unknown"] {
        store.subscribe(session, uri, None).unwrap();
    }
    tokio::time::sleep(COLLECT_INTERVAL * 2 + MAINTAIN_TICK * 2).await;
    let mut left = store.subscribers_for(uri);
    left.sort();
    assert_eq!(left, vec!["session-live", "session-unknown"]);
}

/// Rows an older build wrote have no demand marker; after an upgrade the
/// first sweep writes it, and the URI's watcher starts.
#[tokio::test(start_paused = true)]
async fn rows_without_a_marker_get_one_and_a_watcher() {
    let uri = "res://upgraded";
    let fleet = Fleet::new(&[uri]);
    let a = fleet.replica().await;
    passes(1).await;

    let store = fleet.store();
    store.subscribe("session-old", uri, None).unwrap();
    // As an older build leaves it: the row, no marker.
    fleet
        .kv
        .delete(&format!(
            "sub:w:{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, uri)
        ))
        .await
        .unwrap();
    assert!(!fleet.state().has_demand(uri).await.unwrap());
    passes(1).await;
    assert_eq!(a.running().await, 0, "no marker, no watcher");

    tokio::time::sleep(COLLECT_INTERVAL + MAINTAIN_TICK * 2).await;
    assert!(fleet.state().has_demand(uri).await.unwrap());
    assert_eq!(a.running().await, 1);
}

/// A replica that finds itself gone from the store writes the rows of its
/// streams again: another replica's sweeper may have removed them.
#[tokio::test(start_paused = true)]
async fn a_replica_found_gone_from_the_store_writes_its_rows_again() {
    let uri = "res://rejoin";
    let fleet = Fleet::new(&[uri]);
    let a = fleet.replica().await;
    passes(1).await;
    let _lease = a.subscribe("session-r", uri).await;

    let member = a.engine.member_id().expect("member").to_owned();
    fleet.state().leave(&member).await.unwrap();
    fleet.state().remove_row("session-r", uri).await.unwrap();
    assert!(fleet.store().subscribers_for(uri).is_empty());

    passes(1).await;
    drain().await;
    assert_eq!(fleet.store().subscribers_for(uri), vec!["session-r"]);
    assert!(fleet.state().has_demand(uri).await.unwrap());
}

/// A poll watcher that stops because nobody is subscribed clears its
/// baseline, so a later watcher starts from what it reads then.
#[tokio::test(start_paused = true)]
async fn a_watcher_stopped_for_want_of_subscribers_clears_its_baseline() {
    let uri = "res://cleared";
    let fleet = Fleet::new(&[uri]);
    fleet.set(uri, "v1");
    let a = fleet.replica().await;
    passes(1).await;

    let lease = a.subscribe("session-c", uri).await;
    tokio::time::sleep(POLL + Duration::from_secs(1)).await;
    assert!(fleet.state().baseline(uri).await.unwrap().is_some());

    drop(lease);
    drain().await;
    assert_eq!(a.running().await, 0);
    assert!(fleet.state().baseline(uri).await.unwrap().is_none());
}

/// Without a coordinator, a replica holds every shard.
#[tokio::test(start_paused = true)]
async fn a_replica_without_a_coordinator_holds_every_shard() {
    let uri = "res://single";
    let fleet = Fleet::new(&[uri]);
    let store: Arc<dyn SubscriptionStore> = Arc::new(fleet.store());
    let engine = WatchEngine::start(
        fleet.configs.clone(),
        Arc::clone(&store),
        Arc::new(|_: &str, _: DeliveryMessage| {}),
        Arc::new(|_: &str| None),
    );
    engine.attach_cluster(WatchCluster::default()).await;
    passes(1).await;
    assert_eq!(engine.owned_shards().await.len(), WATCH_SHARDS as usize);

    let service = SubscriptionService::new(store, engine.clone());
    let _lease = service
        .acquire("session-1", uri, identity("session-1"))
        .await
        .unwrap();
    drain().await;
    assert_eq!(engine.active_watch_count().await, 1);
}
