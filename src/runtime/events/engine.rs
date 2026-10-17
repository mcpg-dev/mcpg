//! The events core: the stores, the catalog, the events-owner loop and the
//! inbound routes, kept across config reloads.
//!
//! A reload rebuilds the plugin registry and the runtime; if the core lived in
//! the runtime, each reload would drop the owner lease without releasing it
//! and restart every source. The core is installed once into the shared
//! services bundle that the reload carries to every new runtime, and takes
//! each new config through [`EventsCore::prepare`] (which fails the reload
//! when a declaration does not compile) and [`EventsCore::commit`].
//!
//! Stores are kept across reloads while they live in this process (memory,
//! file, or a single node's coordinator), so a reload loses nothing. A
//! distributed coordinator's store is resolved again from the new registry,
//! because the old registry's coordinator is shut down; the owner lease
//! taken on it is released first, so no replica waits out its TTL.
//!
//! One replica at a time is the events owner (leadership role
//! `events-owner`; on a single node always this one). Only the owner runs
//! sources, writes logs, drains inboxes and reaps. Every other replica
//! serves `events/list`, subscription writes and inbound routes.
//!
//! The catalog in force is the configured types and the types the
//! federations of the runtime in force imported. The core follows the
//! runtime's imports between reloads, so an upstream's change to its event
//! types reaches `events/list` without one.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use futures::StreamExt as _;
use mcpg_cluster_api::{BoxActiveLease, ClusterBackend, KeyValueStore, PubSub};
use mcpg_safe_egress::SafeEgress;
use tokio::sync::{Notify, watch};

use super::catalog::{EventCatalog, EventType, FederatedEvents, SourceSpec};
use super::delivery::{EgressFactory, egress_policy};
use super::dispatcher::{DISPATCH_TICK, Dispatcher};
use super::inbound::{Handshake, InboundRejection, extract_event_id, extract_timestamp};
use super::index::SubscriptionIndex;
use super::keys::EventsKeys;
use super::log::{EventLog, InboxLimits, InboxOutcome, InboxRow, WriterLease};
use super::occurrence::{RawOccurrence, shape};
use super::poll::LeaseStore;
use super::sources::{ResourceFetcher, SourceContext, SourceManager, meter_ingest};
use super::subscriptions::{HintOp, RECORD_GRACE, SubscriptionHint, SubscriptionStore, TtlPolicy};
use super::verifier::InFlightHosts;
use crate::config::events::{EventStoreClass, EventsConfig};
use crate::config::{AppConfig, StoreOverrideConfig};
use crate::runtime::GatewayRuntime;
use crate::runtime::cp_quota::EventsPlan;

/// The MCP Events part of the plan `runtime` was last told about.
pub(crate) fn plan_of(runtime: &GatewayRuntime) -> EventsPlan {
    runtime
        .cp_quota_status
        .current()
        .map(|status| status.events)
        .unwrap_or_default()
}

/// Leadership role of the events owner.
pub const OWNER_ROLE: &str = "events-owner";
/// TTL of the owner lease.
pub const OWNER_LEASE_TTL: Duration = Duration::from_secs(15);
/// Interval of the owner loop.
pub const OWNER_TICK: Duration = Duration::from_secs(2);
/// Interval at which the owner drains inboxes nobody hinted about.
pub const INBOX_POLL: Duration = Duration::from_secs(5);
/// Interval of retention passes.
pub const RETENTION_INTERVAL: Duration = Duration::from_secs(30);
/// Interval at which the owner rebuilds its subscription index.
pub const INDEX_RESYNC: Duration = Duration::from_secs(300);
/// Interval of the subscription reaper.
pub const REAPER_INTERVAL: Duration = Duration::from_secs(60);
/// Dispatcher shards. Each is a fenced lock: the replicas share them out,
/// and the shards of a replica that dies pass on when their leases expire.
pub const DISPATCH_SHARDS: u32 = 32;
/// Lock key prefix of a dispatcher shard.
const SHARD_LOCK_PREFIX: &str = "events-shard-";
/// The coordinator store of its own the events stores ask for.
const EVENTS_BUCKET: &str = "events";
/// How stale a replica's view of the admin delivery pause may be.
const ADMIN_PAUSE_READ_MS: u64 = 2_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What decides whether a store resolved for one config serves the next.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreOrigin {
    store: Option<StoreOverrideConfig>,
    log_store: Option<StoreOverrideConfig>,
    cluster_kind: String,
    tenant_segment: Option<String>,
    state_key_env: Option<String>,
    keys_fingerprint: [u8; 32],
}

impl StoreOrigin {
    fn of(config: &AppConfig, keys: &EventsKeys) -> Self {
        let events = &config.mcp.configurations.events;
        Self {
            store: events.store.clone(),
            log_store: events.log_store.clone(),
            cluster_kind: config.cluster.kind.clone(),
            tenant_segment: config.cluster.tenant_segment.clone(),
            state_key_env: config.cluster.state_encryption_key_env.clone(),
            keys_fingerprint: *keys.fingerprint(),
        }
    }
}

/// The stores and keys the core runs on.
pub struct EventsStores {
    pub keys: Arc<EventsKeys>,
    pub log: Arc<EventLog>,
    pub subscriptions: Arc<SubscriptionStore>,
    /// Poll and stream leases, in the subscription store.
    pub leases: Arc<LeaseStore>,
    /// The routes of upstream webhook subscriptions, in the subscription
    /// store.
    pub routes: Arc<super::upstream_webhook::RouteStore>,
    pub bus: Option<Arc<dyn PubSub>>,
    /// The coordinator the owner lease is taken on; `None` runs as the
    /// sole owner.
    pub backend: Option<Arc<dyn ClusterBackend>>,
    /// Whether subscription records survive a restart.
    pub subscriptions_durable: bool,
    origin: StoreOrigin,
    in_process: bool,
}

impl std::fmt::Debug for EventsStores {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsStores")
            .field("keys", &self.keys)
            .field("subscriptions_durable", &self.subscriptions_durable)
            .finish_non_exhaustive()
    }
}

impl EventsStores {
    /// Stores over explicit primitives, for tests and embedding.
    pub fn new(
        keys: Arc<EventsKeys>,
        log_kv: Arc<dyn KeyValueStore>,
        subscription_kv: Arc<dyn KeyValueStore>,
        bus: Option<Arc<dyn PubSub>>,
        backend: Option<Arc<dyn ClusterBackend>>,
        subscriptions_durable: bool,
    ) -> Self {
        Self {
            log: Arc::new(EventLog::new(log_kv, bus.clone(), Arc::clone(&keys))),
            subscriptions: Arc::new(SubscriptionStore::new(
                Arc::clone(&subscription_kv),
                bus.clone(),
                Arc::clone(&keys),
            )),
            leases: Arc::new(LeaseStore::new(
                Arc::clone(&subscription_kv),
                bus.clone(),
                Arc::clone(&keys),
            )),
            routes: Arc::new(super::upstream_webhook::RouteStore::new(subscription_kv)),
            origin: StoreOrigin {
                store: None,
                log_store: None,
                cluster_kind: String::new(),
                tenant_segment: None,
                state_key_env: None,
                keys_fingerprint: *keys.fingerprint(),
            },
            keys,
            bus,
            backend,
            subscriptions_durable,
            in_process: true,
        }
    }
}

/// A config the core has checked and compiled, ready to commit.
pub struct PreparedEvents {
    config: EventsConfig,
    stores: Option<Arc<EventsStores>>,
    catalog: Arc<EventCatalog>,
    egress: Option<Arc<SafeEgress>>,
    /// The imports of the runtime the config comes with, from the value
    /// `catalog` holds.
    imports: Option<watch::Receiver<FederatedEvents>>,
    imports_pending: bool,
    public_address: PublicAddress,
}

/// Where third parties reach this gateway, for the callbacks of upstream
/// webhook subscriptions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicAddress {
    /// `gateway.server.canonical_url`.
    pub canonical_url: Option<String>,
    /// Whether a public address exists or comes: a canonical URL, or a
    /// public tunnel whose relay assigns one.
    pub callbacks: bool,
}

impl PublicAddress {
    fn of(config: &AppConfig) -> Self {
        let server = &config.gateway.server;
        let canonical_url = server
            .canonical_url
            .as_deref()
            .map(|url| url.trim_end_matches('/').to_owned());
        let public_tunnel = server.tunnel.as_ref().is_some_and(|tunnel| {
            tunnel.enabled && tunnel.exposure == crate::config::TunnelExposure::Public
        });
        Self {
            callbacks: canonical_url.is_some() || public_tunnel,
            canonical_url,
        }
    }
}

/// Retry after an import could not be put in force.
const IMPORT_RETRY: Duration = Duration::from_secs(5);

/// The outcome of one inbound request.
#[derive(Debug, Clone, PartialEq)]
pub enum InboundReply {
    /// No served source has this id.
    NotFound,
    /// Durably written for every type that keeps it; the sender may
    /// forget it.
    Accepted,
    /// Verified, but outside every type's `when` filter; acknowledged and
    /// dropped.
    Ignored,
    /// A handshake of the route's signing profile: acknowledged, or
    /// answered with this JSON object.
    Handshake(Option<serde_json::Value>),
    /// The signature is missing or wrong.
    Unauthorized,
    /// The signed timestamp is outside the tolerance.
    Stale,
    /// The body is not a JSON object.
    BadRequest,
    /// Too many requests; retry after the given time.
    RateLimited(Duration),
    /// The inbox cannot take the event now; retry after the given time.
    Unavailable(Duration),
}

#[derive(Default)]
struct OwnerState {
    lease: Option<BoxActiveLease>,
    lease_backend: Option<Arc<dyn ClusterBackend>>,
    sources: SourceManager,
    /// Sources that run on every replica, owner or not.
    replica_sources: SourceManager,
    owner: bool,
    last_index_ms: u64,
    last_retention_ms: u64,
    last_reap_ms: u64,
    last_inbox_ms: u64,
    listeners: Vec<tokio::task::JoinHandle<()>>,
    listeners_for: Option<usize>,
    /// The dispatcher shards this replica holds.
    shards: BTreeMap<u32, BoxActiveLease>,
    shards_backend: Option<Arc<dyn ClusterBackend>>,
    /// Whether the plan held the sources at the owner's last tick.
    ingest_held: bool,
}

impl Drop for OwnerState {
    fn drop(&mut self) {
        for listener in self.listeners.drain(..) {
            listener.abort();
        }
    }
}

/// The events core. See the [module docs](self).
pub struct EventsCore {
    config: ArcSwap<EventsConfig>,
    catalog: ArcSwap<EventCatalog>,
    stores: ArcSwapOption<EventsStores>,
    lease_tx: watch::Sender<Option<WriterLease>>,
    runtime: parking_lot::RwLock<Weak<ArcSwap<GatewayRuntime>>>,
    generation: AtomicU64,
    index: parking_lot::RwLock<SubscriptionIndex>,
    inbox_nudge: Notify,
    owner: tokio::sync::Mutex<OwnerState>,
    loop_started: AtomicBool,
    egress: ArcSwapOption<SafeEgress>,
    egress_factory: parking_lot::RwLock<Option<EgressFactory>>,
    verifying_hosts: Arc<InFlightHosts>,
    dispatcher: tokio::sync::Mutex<Dispatcher>,
    /// Subscriptions whose record changed since the dispatcher read it.
    stale: parking_lot::Mutex<HashSet<String>>,
    /// Subscriptions of types the config no longer declares, for the
    /// dispatcher to end.
    orphans: parking_lot::Mutex<HashSet<String>>,
    /// The dispatcher shards this replica holds, with each lock's fence.
    shard_leases: parking_lot::RwLock<HashMap<u32, WriterLease>>,
    /// The lease demand this replica last wrote per type, so a poll or a
    /// stream writes it only when it would otherwise lapse soon.
    demand_written: parking_lot::Mutex<HashMap<String, u64>>,
    /// The head of each log as this replica last saw it, for its streams.
    pub(super) heads: parking_lot::Mutex<HashMap<String, Weak<super::push::HeadWatch>>>,
    /// `events/stream` responses open on this replica.
    pub(super) open_streams: std::sync::atomic::AtomicUsize,
    /// Every type the config and the imports compile to; `catalog` is what
    /// of it the plan's type cap serves.
    compiled: ArcSwap<EventCatalog>,
    /// The type cap `catalog` was cut to; `0` for none.
    types_limit: AtomicU64,
    /// Moves whenever the catalog in force changes: on every commit, when
    /// the imported types change, and when the plan's type cap does.
    catalog_version: AtomicU64,
    /// Held across a catalog swap, so a commit and an import never
    /// interleave.
    catalog_swap: tokio::sync::Mutex<()>,
    /// Follows the imports of the runtime in force.
    importer: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// A federation has no import yet: a subscription of a type the
    /// catalog lacks may be of a type still to come, so it is kept.
    imports_pending: AtomicBool,
    /// The owner rereads the subscription index at its next tick.
    reindex: AtomicBool,
    /// Where third parties reach this gateway, per the config in force.
    public_address: ArcSwap<PublicAddress>,
    /// The admin API's delivery pause as this replica last read it, and
    /// when.
    admin_pause: parking_lot::Mutex<(bool, u64)>,
}

impl Drop for EventsCore {
    fn drop(&mut self) {
        if let Some(importer) = self.importer.get_mut().take() {
            importer.abort();
        }
    }
}

impl std::fmt::Debug for EventsCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsCore")
            .field("enabled", &self.config.load().enabled)
            .field("types", &self.catalog.load().len())
            .finish_non_exhaustive()
    }
}

impl Default for EventsCore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventsCore {
    /// A dormant core: no config, no stores, no owner loop.
    pub fn new() -> Self {
        Self {
            config: ArcSwap::from_pointee(EventsConfig::default()),
            catalog: ArcSwap::from_pointee(EventCatalog::empty()),
            stores: ArcSwapOption::empty(),
            lease_tx: watch::channel(None).0,
            runtime: parking_lot::RwLock::new(Weak::new()),
            generation: AtomicU64::new(0),
            index: parking_lot::RwLock::new(SubscriptionIndex::default()),
            inbox_nudge: Notify::new(),
            owner: tokio::sync::Mutex::new(OwnerState::default()),
            loop_started: AtomicBool::new(false),
            egress: ArcSwapOption::empty(),
            egress_factory: parking_lot::RwLock::new(None),
            verifying_hosts: Arc::default(),
            dispatcher: tokio::sync::Mutex::new(Dispatcher::default()),
            stale: parking_lot::Mutex::new(HashSet::new()),
            orphans: parking_lot::Mutex::new(HashSet::new()),
            shard_leases: parking_lot::RwLock::new(HashMap::new()),
            demand_written: parking_lot::Mutex::new(HashMap::new()),
            heads: parking_lot::Mutex::new(HashMap::new()),
            open_streams: std::sync::atomic::AtomicUsize::new(0),
            compiled: ArcSwap::from_pointee(EventCatalog::empty()),
            types_limit: AtomicU64::new(0),
            catalog_version: AtomicU64::new(0),
            catalog_swap: tokio::sync::Mutex::new(()),
            importer: parking_lot::Mutex::new(None),
            imports_pending: AtomicBool::new(false),
            reindex: AtomicBool::new(false),
            public_address: ArcSwap::from_pointee(PublicAddress::default()),
            admin_pause: parking_lot::Mutex::new((false, 0)),
        }
    }

    /// The base URL upstreams deliver webhooks to:
    /// `gateway.server.canonical_url`, else the URL a public tunnel's relay
    /// assigned, while the tunnel is up.
    pub(crate) fn callback_base(&self) -> Option<String> {
        if let Some(url) = &self.public_address.load().canonical_url {
            return Some(url.clone());
        }
        let runtime = self.runtime()?;
        let services = runtime.load().shared_services.load_full()?;
        services
            .tunnel_public_url
            .load()
            .as_deref()
            .map(|url| url.trim_end_matches('/').to_owned())
    }

    /// `events/stream` responses open on this replica.
    pub fn open_streams(&self) -> usize {
        self.open_streams.load(Ordering::Relaxed)
    }

    /// Wake the owner loop to drain the inboxes now.
    pub(super) fn nudge_inbox(&self) {
        self.inbox_nudge.notify_one();
    }

    /// Build the outbound webhook client with `factory` from the next
    /// config on. Tests use it to reach receivers on loopback.
    pub fn set_egress_factory(&self, factory: EgressFactory) {
        *self.egress_factory.write() = Some(factory);
    }

    /// The outbound webhook client of the config in force.
    pub fn egress(&self) -> Option<Arc<SafeEgress>> {
        self.egress.load_full()
    }

    pub(crate) fn verifying_hosts(&self) -> &Arc<InFlightHosts> {
        &self.verifying_hosts
    }

    pub(crate) fn dispatcher(&self) -> &tokio::sync::Mutex<Dispatcher> {
        &self.dispatcher
    }

    /// The config generation: it moves on every commit.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The catalog version: it moves whenever the catalog in force changes.
    pub(crate) fn catalog_version(&self) -> u64 {
        self.catalog_version.load(Ordering::SeqCst)
    }

    /// The subscriptions marked changed since the last call.
    pub(crate) fn take_stale(&self) -> HashSet<String> {
        std::mem::take(&mut *self.stale.lock())
    }

    /// The subscriptions of removed types found since the last call.
    pub(crate) fn take_orphans(&self) -> HashSet<String> {
        std::mem::take(&mut *self.orphans.lock())
    }

    /// The dispatcher shards this replica holds at `now_ms`.
    pub(crate) fn held_shards(&self, now_ms: u64) -> HashMap<u32, WriterLease> {
        self.shard_leases
            .read()
            .iter()
            .filter(|(_, lease)| lease.expires_at_ms > now_ms)
            .map(|(shard, lease)| (*shard, *lease))
            .collect()
    }

    /// The lease of dispatcher shard `shard`, when this replica holds it.
    pub(crate) fn shard_lease(&self, shard: u32) -> Option<WriterLease> {
        self.shard_leases.read().get(&shard).copied()
    }

    /// Ids of the live subscriptions of `name`.
    pub(crate) fn live_ids(&self, name: &str, now_ms: u64) -> Vec<String> {
        self.index.read().live_ids(name, now_ms)
    }

    /// Live subscriptions of `name`, and of every type.
    pub(crate) fn live_counts(&self, name: &str, now_ms: u64) -> (usize, usize) {
        let index = self.index.read();
        (index.live_count(name, now_ms), index.total_live(now_ms))
    }

    /// Admit a new reader of `ty` under the plan's reader cap, or refuse it
    /// with `-32013 {limit: "plan.event_subscriptions"}`. The cap counts
    /// every live reader on this gateway, webhook subscriptions, poll leases
    /// and open streams, and the upstream subscriptions held for imported
    /// types. A reader of an imported type whose demand no upstream
    /// subscription serves yet adds one of those too.
    pub(crate) async fn check_plan_readers(
        &self,
        ty: &EventType,
        holder: &super::federated::LeaseHolder<'_>,
    ) -> Result<(), crate::protocol::v_2026_07_28::extensions::events::errors::EventsError> {
        use crate::protocol::v_2026_07_28::extensions::events::errors::EventsError;
        let Some(limit) = self.plan().readers_limit.filter(|limit| *limit > 0) else {
            return Ok(());
        };
        let fault = |_| EventsError::internal("the event store is unavailable; retry");
        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal("the event store is unavailable; retry"))?;
        let cap = usize::try_from(limit).unwrap_or(usize::MAX);
        let adds = match &ty.source {
            SourceSpec::Federation { sharing, .. } => {
                let key = super::federated::Demand::of(*sharing, holder).key(&stores.keys);
                let served = stores
                    .leases
                    .has_upstream(&ty.name, &key)
                    .await
                    .map_err(fault)?;
                if served { 1 } else { 2 }
            }
            _ => 1,
        };
        // Webhook subscriptions come from the index; the other kinds are
        // counted in the store, each only up to where the cap is passed.
        let mut used = self.live_counts(&ty.name, now_ms()).1;
        for kind in 0..3 {
            if used.saturating_add(adds) > cap {
                break;
            }
            let room = cap.saturating_add(1).saturating_sub(used);
            used += match kind {
                0 => stores.leases.count_all_leases(room).await,
                1 => stores.leases.count_all_streams(room).await,
                _ => stores.leases.count_upstreams(room).await,
            }
            .map_err(fault)?;
        }
        if used.saturating_add(adds) > cap {
            return Err(EventsError::resource_exhausted(
                "plan.event_subscriptions",
                Some(limit),
            ));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // What the rest of the gateway reads
    // -----------------------------------------------------------------------

    /// `mcp.configurations.events` in force.
    pub fn config(&self) -> Arc<EventsConfig> {
        self.config.load_full()
    }

    /// The catalog in force.
    pub fn catalog(&self) -> Arc<EventCatalog> {
        self.catalog.load_full()
    }

    /// The stores, once events have been enabled.
    pub fn stores(&self) -> Option<Arc<EventsStores>> {
        self.stores.load_full()
    }

    /// Whether an operator holds every delivery: by config, or from the
    /// admin API. The admin flag is read from the store at most every
    /// [`ADMIN_PAUSE_READ_MS`]; this replica's own change applies at once.
    pub(crate) async fn operator_paused(&self) -> bool {
        if self.config().delivery_paused {
            return true;
        }
        let now = now_ms();
        let (cached, read_at) = *self.admin_pause.lock();
        if now.saturating_sub(read_at) < ADMIN_PAUSE_READ_MS {
            return cached;
        }
        let Some(stores) = self.stores() else {
            return false;
        };
        let paused = stores
            .subscriptions
            .delivery_paused()
            .await
            .unwrap_or(cached);
        *self.admin_pause.lock() = (paused, now);
        paused
    }

    /// Record the admin API's pause as this replica just set it.
    pub(crate) fn note_admin_pause(&self, paused: bool) {
        *self.admin_pause.lock() = (paused, now_ms());
    }

    /// Whether every delivery mode waits now: an operator's pause, or a
    /// plan whose deliveries for the period are used. Held events stay in
    /// the log within retention.
    pub(crate) async fn delivery_held(&self, runtime: &GatewayRuntime) -> bool {
        self.operator_paused().await || plan_of(runtime).deliveries_held
    }

    /// The plan's MCP Events caps now; no caps while no runtime is up.
    pub(crate) fn plan(&self) -> EventsPlan {
        self.runtime()
            .map(|runtime| plan_of(&runtime.load()))
            .unwrap_or_default()
    }

    /// Whether the plan's ingests for the period are used: every source
    /// but the builtin ones waits, and an inbound or upstream webhook is
    /// answered 429 until the period ends.
    pub(crate) fn ingest_held(&self) -> bool {
        self.plan().ingest_held
    }

    /// The grant policy for a subscribe now.
    pub fn ttl_policy(&self) -> TtlPolicy {
        let durable = self
            .stores
            .load()
            .as_ref()
            .is_some_and(|s| s.subscriptions_durable);
        TtlPolicy::from_config(&self.config.load(), durable)
    }

    /// The owner lease of this replica, `None` while another replica owns
    /// the logs. Watch it to start and stop owner-only work.
    pub fn owner_lease(&self) -> watch::Receiver<Option<WriterLease>> {
        self.lease_tx.subscribe()
    }

    /// Whether this replica is the events owner now.
    pub fn is_owner(&self) -> bool {
        self.lease_tx
            .borrow()
            .is_some_and(|lease| lease.expires_at_ms > now_ms())
    }

    /// A copy of the owner's subscription index.
    pub fn subscription_index(&self) -> SubscriptionIndex {
        self.index.read().clone()
    }

    /// Apply a subscription change to this replica's index at once,
    /// without waiting for its hint.
    pub fn note_subscription(&self, hint: &SubscriptionHint) {
        self.index.write().apply(hint);
        if hint.op != HintOp::Lease {
            self.stale.lock().insert(hint.id.clone());
        }
    }

    /// A poll or a stream of type `ty` by `reader` at `now` holds a lease
    /// for `lease_ms`: this replica's index knows at once, and the store and
    /// the other replicas learn it when the demand last written would lapse
    /// within half a lease. An imported type also records what its upstream
    /// subscription needs: the arguments, and for one shared per principal,
    /// the reader.
    pub(crate) async fn note_lease_demand(
        &self,
        stores: &EventsStores,
        ty: &EventType,
        reader: &super::federated::LeaseHolder<'_>,
        now: u64,
        lease_ms: u64,
        ttl: Duration,
    ) {
        let until = now.saturating_add(lease_ms);
        self.index.write().note_lease(&ty.name, until);
        let due = |key: &str| {
            let mut written = self.demand_written.lock();
            match written.get(key) {
                Some(last) if *last > now.saturating_add(lease_ms / 2) => false,
                _ => {
                    written.insert(key.to_owned(), until);
                    true
                }
            }
        };
        if due(&ty.name)
            && let Err(error) = stores.leases.extend_demand(&ty.name, until, ttl).await
        {
            self.demand_written.lock().remove(&ty.name);
            tracing::debug!(event = %ty.name, error = %error, "lease demand could not be written; the next renewal retries");
        }
        let SourceSpec::Federation { sharing, .. } = &ty.source else {
            return;
        };
        let demand = super::federated::Demand::of(*sharing, reader);
        let key = demand.key(&stores.keys);
        let written_key = format!("{}\u{0}{key}", ty.name);
        if due(&written_key)
            && let Err(error) = stores
                .leases
                .extend_argument_demand(&ty.name, &key, &demand, until, ttl)
                .await
        {
            self.demand_written.lock().remove(&written_key);
            tracing::debug!(event = %ty.name, error = %error, "lease demand could not be written; the next renewal retries");
        }
    }

    /// The live runtime.
    pub fn runtime(&self) -> Option<Arc<ArcSwap<GatewayRuntime>>> {
        self.runtime.read().upgrade()
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    /// Check and compile `config` against `runtime`'s plugin registry,
    /// resolving stores when events are on. Nothing changes until
    /// [`Self::commit`]; an error leaves the core as it was.
    pub async fn prepare(
        &self,
        config: &AppConfig,
        runtime: &GatewayRuntime,
    ) -> anyhow::Result<PreparedEvents> {
        let events = config.mcp.configurations.events.clone();
        if !events.enabled {
            return Ok(PreparedEvents {
                config: events,
                stores: self.stores.load_full(),
                catalog: Arc::new(EventCatalog::empty()),
                egress: None,
                imports: None,
                imports_pending: false,
                public_address: PublicAddress::of(config),
            });
        }
        let egress = if events.webhook.enabled {
            let policy = egress_policy(&events.webhook.egress);
            let built = match self.egress_factory.read().clone() {
                Some(factory) => factory(policy),
                None => SafeEgress::new(policy),
            };
            let built = built.map_err(|error| {
                anyhow::anyhow!("mcp.configurations.events.webhook.egress: {error}")
            })?;
            if let Some(url) = &events.webhook.egress.probe_url {
                built.check_url(url).map_err(|refusal| {
                    anyhow::anyhow!("mcp.configurations.events.webhook.egress.probe_url: {refusal}")
                })?;
            }
            Some(Arc::new(built))
        } else {
            None
        };
        let current = self.stores.load_full();
        let keys = match EventsKeys::from_config(config)? {
            Some(keys) => Arc::new(keys),
            None if events.webhook.enabled => anyhow::bail!(
                "mcp.configurations.events: webhook delivery needs a key every replica shares; \
                 set cluster.state_encryption_key_env or \
                 mcp.configurations.sessions.synthetic_session_key"
            ),
            None => match &current {
                Some(stores) if !stores.keys.is_stable() => Arc::clone(&stores.keys),
                _ => Arc::new(EventsKeys::process()),
            },
        };
        let origin = StoreOrigin::of(config, &keys);
        let stores = match current {
            Some(stores) if stores.in_process && stores.origin == origin => stores,
            _ => Arc::new(resolve_stores(config, runtime, keys, origin).await?),
        };
        let mut catalog =
            EventCatalog::build(config, &stores.keys, &runtime.plugin_registry_arc()).await?;
        catalog.assign_schema_epochs(&stores.log).await?;
        let public_address = PublicAddress::of(config);
        let mut imports = runtime.federated_events();
        let imported = imports.borrow_and_update().clone();
        let catalog = with_imports(
            &catalog,
            &imported,
            &events,
            &stores,
            public_address.callbacks,
        )
        .await?;
        Ok(PreparedEvents {
            config: events,
            stores: Some(stores),
            catalog: Arc::new(catalog),
            egress,
            imports: Some(imports),
            imports_pending: imported.pending,
            public_address,
        })
    }

    /// Put a prepared config in force and make sure the owner loop runs.
    /// Returns whether what `events/list` describes changed: a type came,
    /// went, or changed its descriptor.
    pub async fn commit(
        self: &Arc<Self>,
        prepared: PreparedEvents,
        runtime: &Arc<ArcSwap<GatewayRuntime>>,
    ) -> bool {
        *self.runtime.write() = Arc::downgrade(runtime);
        {
            let mut owner = self.owner.lock().await;
            let backend_changed = match (&owner.lease_backend, &prepared.stores) {
                (Some(held), Some(stores)) => stores
                    .backend
                    .as_ref()
                    .is_none_or(|next| !same_backend(held, next)),
                (Some(_), None) => true,
                _ => false,
            };
            if backend_changed || !prepared.config.enabled {
                self.release_shards(&mut owner, None).await;
                step_down(&mut owner, &self.lease_tx).await;
            }
            owner.last_index_ms = 0;
        }
        let probe = {
            let before = self.config.load();
            let unchanged = before.enabled
                && before.webhook.enabled
                && before.webhook.egress == prepared.config.webhook.egress;
            prepared
                .egress
                .clone()
                .zip(prepared.config.webhook.egress.probe_url.clone())
                .filter(|_| !unchanged)
        };
        if let Some((egress, url)) = probe {
            tokio::spawn(probe_egress(egress, url));
        }
        let enabled = prepared.config.enabled;
        let (listed_changed, generation) = {
            let _swap = self.catalog_swap.lock().await;
            let served = self.serve(prepared.catalog);
            let listed_changed = listed(&self.catalog.load()) != listed(&served);
            self.config.store(Arc::new(prepared.config));
            self.catalog.store(served);
            self.stores.store(prepared.stores);
            self.egress.store(prepared.egress);
            self.imports_pending
                .store(prepared.imports_pending, Ordering::SeqCst);
            self.public_address.store(Arc::new(prepared.public_address));
            self.catalog_version.fetch_add(1, Ordering::SeqCst);
            (
                listed_changed,
                self.generation.fetch_add(1, Ordering::SeqCst) + 1,
            )
        };
        let follower = prepared
            .imports
            .map(|imports| tokio::spawn(follow_imports(Arc::downgrade(self), imports, generation)));
        if let Some(previous) = std::mem::replace(&mut *self.importer.lock(), follower) {
            previous.abort();
        }
        if enabled && !self.loop_started.swap(true, Ordering::SeqCst) {
            tokio::spawn(owner_loop(Arc::downgrade(self)));
            tokio::spawn(dispatch_loop(Arc::downgrade(self)));
        }
        self.inbox_nudge.notify_one();
        listed_changed
    }

    /// Prepare and commit `config` in one step.
    pub async fn apply(
        self: &Arc<Self>,
        config: &AppConfig,
        runtime: &Arc<ArcSwap<GatewayRuntime>>,
    ) -> anyhow::Result<()> {
        let prepared = self.prepare(config, &runtime.load()).await?;
        let _ = self.commit(prepared, runtime).await;
        Ok(())
    }

    /// Keep `compiled` as every type there is, and return what of it the
    /// plan's type cap serves. Called under `catalog_swap`.
    fn serve(&self, compiled: Arc<EventCatalog>) -> Arc<EventCatalog> {
        let limit = self.plan().types_limit.unwrap_or(0);
        self.compiled.store(Arc::clone(&compiled));
        self.types_limit.store(limit, Ordering::SeqCst);
        let cut = usize::try_from(limit)
            .ok()
            .filter(|limit| *limit > 0)
            .and_then(|limit| compiled.within(limit));
        match cut {
            Some((served, left_out)) => {
                tracing::warn!(
                    limit,
                    left_out = ?left_out,
                    "the plan serves {limit} event types: these are not served"
                );
                Arc::new(served)
            }
            None => compiled,
        }
    }

    /// The compiled types the plan's type cap leaves out now.
    pub(crate) fn types_not_served(&self) -> usize {
        self.compiled
            .load()
            .len()
            .saturating_sub(self.catalog.load().len())
    }

    /// Serve within the plan's type cap when it changed since the catalog
    /// was cut, and announce a change of what `events/list` describes.
    async fn follow_type_cap(&self) {
        let limit = self.plan().types_limit.unwrap_or(0);
        if self.types_limit.load(Ordering::SeqCst) == limit {
            return;
        }
        let listed_changed = {
            let _swap = self.catalog_swap.lock().await;
            let served = self.serve(self.compiled.load_full());
            let listed_changed = listed(&self.catalog.load()) != listed(&served);
            self.catalog.store(served);
            self.catalog_version.fetch_add(1, Ordering::SeqCst);
            listed_changed
        };
        self.reindex.store(true, Ordering::SeqCst);
        if listed_changed && let Some(runtime) = self.runtime() {
            let runtime = runtime.load();
            super::builtin::announce_list_changed(runtime.session_store(), runtime.delivery_bus());
        }
    }

    /// Serve `imported` beside the configured types. `Ok(false)` when the
    /// config generation moved on from `generation`: the runtime these
    /// imports come from is no longer in force. A change of what
    /// `events/list` describes is announced.
    async fn import(
        &self,
        imported: &super::catalog::ImportedEvents,
        generation: u64,
    ) -> anyhow::Result<bool> {
        let listed_changed = {
            let _swap = self.catalog_swap.lock().await;
            if self.generation() != generation {
                return Ok(false);
            }
            let config = self.config.load_full();
            let Some(stores) = self.stores.load_full().filter(|_| config.enabled) else {
                return Ok(true);
            };
            let compiled = self.compiled.load_full();
            let callbacks = self.public_address.load().callbacks;
            let next = with_imports(
                &compiled.configured(),
                imported,
                &config,
                &stores,
                callbacks,
            )
            .await?;
            let served = self.serve(Arc::new(next));
            let listed_changed = listed(&self.catalog.load()) != listed(&served);
            self.catalog.store(served);
            self.imports_pending
                .store(imported.pending, Ordering::SeqCst);
            self.catalog_version.fetch_add(1, Ordering::SeqCst);
            listed_changed
        };
        self.reindex.store(true, Ordering::SeqCst);
        if listed_changed && let Some(runtime) = self.runtime() {
            let runtime = runtime.load();
            super::builtin::announce_list_changed(runtime.session_store(), runtime.delivery_bus());
        }
        Ok(true)
    }

    /// Stop every source and release the owner lease.
    pub async fn shutdown(&self) {
        let mut owner = self.owner.lock().await;
        self.release_shards(&mut owner, None).await;
        step_down(&mut owner, &self.lease_tx).await;
        owner.replica_sources.stop_all();
    }

    /// Hold this replica's share of the dispatcher shards: renew what it
    /// holds, hand off what is above its share of the live replicas, and
    /// take free shards up to that share.
    async fn maintain_shards(
        &self,
        owner: &mut OwnerState,
        stores: &EventsStores,
        config: &EventsConfig,
    ) {
        if !config.webhook.enabled {
            self.release_shards(owner, None).await;
            return;
        }
        let Some(backend) = &stores.backend else {
            let lease = WriterLease {
                fence: 0,
                expires_at_ms: now_ms() + OWNER_LEASE_TTL.as_millis() as u64,
            };
            *self.shard_leases.write() = (0..DISPATCH_SHARDS).map(|s| (s, lease)).collect();
            return;
        };
        if owner
            .shards_backend
            .as_ref()
            .is_some_and(|held| !same_backend(held, backend))
        {
            self.release_shards(owner, None).await;
        }
        owner.shards_backend = Some(Arc::clone(backend));

        let mut lost = Vec::new();
        for (shard, lease) in &owner.shards {
            if let Err(error) = lease.renew().await {
                tracing::warn!(shard, error = %error, "lost a dispatcher shard lease; another replica takes it");
                lost.push(*shard);
            }
        }
        for shard in lost {
            owner.shards.remove(&shard);
            self.shard_leases.write().remove(&shard);
        }

        let node = backend.node_info().await.node_id;
        let mut nodes: BTreeSet<String> = backend
            .list_peers()
            .await
            .into_iter()
            .map(|peer| peer.node_id)
            .collect();
        nodes.insert(node.clone());
        let share = DISPATCH_SHARDS.div_ceil(nodes.len() as u32) as usize;
        let extra: Vec<u32> = owner
            .shards
            .keys()
            .rev()
            .take(owner.shards.len().saturating_sub(share))
            .copied()
            .collect();
        if !extra.is_empty() {
            self.release_shards(owner, Some(&extra)).await;
        }
        let start = shard_offset(&node);
        for i in 0..DISPATCH_SHARDS {
            if owner.shards.len() >= share {
                break;
            }
            let shard = (start + i) % DISPATCH_SHARDS;
            if owner.shards.contains_key(&shard) {
                continue;
            }
            match backend
                .try_acquire_lock(&format!("{SHARD_LOCK_PREFIX}{shard}"), OWNER_LEASE_TTL)
                .await
            {
                Ok(Some(lease)) => {
                    owner.shards.insert(shard, lease);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(shard, error = %error, "dispatcher shard acquire failed; next tick");
                    break;
                }
            }
        }
        let held: HashMap<u32, WriterLease> = owner
            .shards
            .iter()
            .map(|(shard, lease)| (*shard, writer_lease(lease)))
            .collect();
        metrics::gauge!("mcpg_events_owned_shards").set(held.len() as f64);
        *self.shard_leases.write() = held;
    }

    /// Hand off the dispatcher shards in `which`, or all of them: settle
    /// and checkpoint their subscriptions, then release the locks while the
    /// dispatcher stays locked, so no pass starts on them in between.
    async fn release_shards(&self, owner: &mut OwnerState, which: Option<&[u32]>) {
        let shards: Vec<u32> = match which {
            Some(which) => which.to_vec(),
            None => self.shard_leases.read().keys().copied().collect(),
        };
        let _dispatcher = self.hand_off_delivery(which).await;
        for shard in &shards {
            self.shard_leases.write().remove(shard);
            if let Some(lease) = owner.shards.remove(shard)
                && let Err(error) = lease.release().await
            {
                tracing::debug!(shard, error = %error, "dispatcher shard release failed; it expires on its own");
            }
        }
        if which.is_none() {
            owner.shards_backend = None;
            metrics::gauge!("mcpg_events_owned_shards").set(0.0);
        }
    }

    /// Start or stop the sources that run on this replica whether or not it
    /// is the owner: they hand what they see to the owner through the
    /// inbox.
    fn reconcile_replica_sources(
        &self,
        owner: &mut OwnerState,
        stores: &Arc<EventsStores>,
        config: &EventsConfig,
    ) {
        let catalog = self.catalog.load_full();
        if !catalog
            .types()
            .iter()
            .any(|ty| ty.source.runs_on_every_replica())
        {
            owner.replica_sources.stop_all();
            return;
        }
        let Some(runtime) = self.runtime().map(|r| r.load_full()) else {
            return;
        };
        if plan_of(&runtime).ingest_held {
            owner.replica_sources.stop_all();
            return;
        }
        let ctx = SourceContext {
            log: Arc::clone(&stores.log),
            lease: self.lease_tx.subscribe(),
            registry: runtime.plugin_registry_arc(),
            fetcher: None,
            max_payload_bytes: config.webhook.max_payload_bytes,
            inbox: Some(InboxLimits {
                ttl: Duration::from_millis(config.log.inbox_ttl_ms),
                max_rows: config.log.inbox_max_rows,
            }),
            core: Weak::new(),
            usage: runtime.tool_call_recorder.clone(),
            quota: runtime.cp_quota_status.clone(),
        };
        let now = now_ms();
        let index = self.index.read().clone();
        owner.replica_sources.reconcile_selected(
            &catalog,
            SourceSpec::runs_on_every_replica,
            &|name| index.has_demand(name, now),
            &ctx,
            self.generation.load(Ordering::SeqCst),
            config.sources.linger_ms,
            now,
        );
    }

    /// Mark, in the log of each type whose source runs on every replica, that
    /// its readers may miss what the source sees while the plan holds it.
    /// Such a source keeps no position to resume from; one on the owner
    /// marks its own gap when it starts again.
    async fn mark_replica_sources_held(
        &self,
        stores: &EventsStores,
        catalog: &EventCatalog,
        plan: &EventsPlan,
        lease: WriterLease,
    ) {
        for ty in catalog
            .types()
            .iter()
            .filter(|ty| ty.source.runs_on_every_replica())
        {
            if let Err(error) = stores
                .log
                .append_gap(
                    &ty.source_key,
                    super::log::GapReason::SourceRestart,
                    super::log::RowScope::default(),
                    &plan.retention(&ty.retention),
                    lease,
                )
                .await
            {
                tracing::warn!(event = %ty.name, error = %error, "could not mark a held event source");
            }
        }
    }

    /// Raise a builtin event: one occurrence of every type whose source is
    /// `builtin`, on any replica. With `audience`, only the subscriptions of
    /// that principal (its trust-qualified key) receive it.
    pub async fn emit_builtin(
        &self,
        builtin: crate::config::events::BuiltinEventSource,
        event_id: Option<String>,
        data: serde_json::Value,
        audience: Option<&str>,
    ) {
        let config = self.config.load();
        if !config.enabled {
            return;
        }
        let Some(stores) = self.stores.load_full() else {
            return;
        };
        let catalog = self.catalog.load();
        let types: Vec<_> = catalog
            .types()
            .iter()
            .filter(|ty| matches!(&ty.source, SourceSpec::Builtin(b) if *b == builtin))
            .cloned()
            .collect();
        if types.is_empty() {
            return;
        }
        let audience = audience.map(|key| audience_hash(&stores.keys, key));
        let limits = InboxLimits {
            ttl: Duration::from_millis(config.log.inbox_ttl_ms),
            max_rows: config.log.inbox_max_rows,
        };
        for ty in types {
            let row = InboxRow {
                v: super::log::FORMAT_VERSION,
                event_id: Some(
                    event_id
                        .clone()
                        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                ),
                timestamp: None,
                data: data.clone(),
                received_at_ms: now_ms(),
                audience: audience.clone(),
                ..InboxRow::default()
            };
            match stores.log.inbox_put(&ty.source_key, row, limits).await {
                Ok(InboxOutcome::Accepted) => self.inbox_nudge.notify_one(),
                Ok(InboxOutcome::Full { .. }) | Err(_) => {
                    metrics::counter!("mcpg_events_sink_dropped_total", "event" => ty.name.clone())
                        .increment(1);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Inbound routes
    // -----------------------------------------------------------------------

    /// Whether the plan refuses one verified webhook into an event log now:
    /// past the per-gateway request ceiling, or while the month's ingests
    /// are used. Names the refusal (`plan_rps` or `ingest_held`) and how
    /// long the sender waits. `surface` labels the ceiling's refusal.
    pub(crate) fn plan_refusal(&self, surface: &'static str) -> Option<(&'static str, Duration)> {
        let runtime = self.runtime()?.load_full();
        if runtime.admit_plan_rps(surface).is_err() {
            return Some(("plan_rps", Duration::from_secs(1)));
        }
        let plan = plan_of(&runtime);
        plan.ingest_held
            .then(|| ("ingest_held", Duration::from_secs(plan.retry_after_secs())))
    }

    /// Serve one POST to `/webhooks/events/{source_id}`.
    pub async fn receive_inbound(
        &self,
        source_id: &str,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> InboundReply {
        let config = self.config.load();
        if !config.enabled {
            return InboundReply::NotFound;
        }
        let Some(stores) = self.stores.load_full() else {
            return InboundReply::NotFound;
        };
        let catalog = self.catalog.load();
        let targets = catalog.by_source_id(source_id);
        // Types that share a route declare the same verify and rate limit,
        // so the first one's stand for the route.
        let Some(&(_, route)) = targets.first() else {
            return InboundReply::NotFound;
        };
        if let Err(wait) = route.rate.take() {
            metrics::counter!("mcpg_events_inbound_total", "outcome" => "rate_limited")
                .increment(1);
            return InboundReply::RateLimited(wait);
        }
        let now_s = now_ms() / 1_000;
        let verified = match route.verifier.verify(headers, body, now_s) {
            Ok(verified) => verified,
            Err(rejection) => {
                let (outcome, reply) = match rejection {
                    InboundRejection::Unauthorized => ("unauthorized", InboundReply::Unauthorized),
                    InboundRejection::Stale => ("stale", InboundReply::Stale),
                };
                metrics::counter!("mcpg_events_inbound_total", "outcome" => outcome).increment(1);
                return reply;
            }
        };
        let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(body)
        else {
            metrics::counter!("mcpg_events_inbound_total", "outcome" => "bad_request").increment(1);
            return InboundReply::BadRequest;
        };
        let json = serde_json::Value::Object(map);
        // A handshake is answered even while the plan holds ingest, so a
        // sender can still set the route up; it is never an event.
        if let Some(handshake) = route.verifier.handshake(headers, &json) {
            let (outcome, reply) = match handshake {
                Handshake::Ack => ("handshake", InboundReply::Handshake(None)),
                Handshake::Reply(object) => (
                    "handshake",
                    InboundReply::Handshake(Some(serde_json::Value::Object(object))),
                ),
                Handshake::Invalid => ("bad_request", InboundReply::BadRequest),
            };
            metrics::counter!("mcpg_events_inbound_total", "outcome" => outcome).increment(1);
            return reply;
        }
        // The plan's limits count verified requests only, so a sender that
        // does not hold the secret cannot use them up.
        if let Some((outcome, wait)) = self.plan_refusal("inbound") {
            metrics::counter!("mcpg_events_inbound_total", "outcome" => outcome).increment(1);
            return InboundReply::RateLimited(wait);
        }
        let limits = InboxLimits {
            ttl: Duration::from_millis(config.log.inbox_ttl_ms),
            max_rows: config.log.inbox_max_rows,
        };
        // An id minted here stays with the rows, so draining one twice after
        // a failover appends it once, and every type of the route shares it.
        let minted = uuid::Uuid::now_v7().to_string();
        let received_at_ms = now_ms();
        let mut kept = 0usize;
        let mut accepted = 0usize;
        let mut failed: Option<(&'static str, Duration)> = None;
        for (ty, spec) in &targets {
            if !spec.filter.keeps(headers, &json) {
                continue;
            }
            kept += 1;
            let row = InboxRow {
                v: super::log::FORMAT_VERSION,
                event_id: Some(
                    extract_event_id(spec.event_id_pointer.as_deref(), &json, &verified)
                        .unwrap_or_else(|| minted.clone()),
                ),
                timestamp: extract_timestamp(spec.timestamp_pointer.as_deref(), &json),
                data: json.clone(),
                received_at_ms,
                ..InboxRow::default()
            };
            let failure = match stores.log.inbox_put(&ty.source_key, row, limits).await {
                Ok(InboxOutcome::Accepted) => {
                    accepted += 1;
                    continue;
                }
                Ok(InboxOutcome::Full { retry_after }) => ("inbox_full", retry_after),
                Err(error) => {
                    tracing::warn!(
                        event = %ty.name,
                        error = %error,
                        "inbound event could not be written to the inbox"
                    );
                    ("store_error", Duration::from_secs(30))
                }
            };
            // The sender retries the whole request; a type that took it
            // already keeps it once, by its event id.
            failed = Some(match failed {
                Some((_, wait)) if wait >= failure.1 => (failure.0, wait),
                _ => failure,
            });
        }
        if accepted > 0 {
            self.inbox_nudge.notify_one();
        }
        let (outcome, reply) = match failed {
            Some((outcome, wait)) => (outcome, InboundReply::Unavailable(wait)),
            None if kept == 0 => ("ignored", InboundReply::Ignored),
            None => ("accepted", InboundReply::Accepted),
        };
        metrics::counter!("mcpg_events_inbound_total", "outcome" => outcome).increment(1);
        reply
    }

    // -----------------------------------------------------------------------
    // The owner loop
    // -----------------------------------------------------------------------

    /// One pass of the owner loop. Public so tests can drive it.
    pub async fn owner_tick(self: &Arc<Self>) {
        let config = self.config.load_full();
        let stores = self.stores.load_full();
        let mut owner = self.owner.lock().await;
        let Some(stores) = stores.filter(|_| config.enabled) else {
            self.release_shards(&mut owner, None).await;
            step_down(&mut owner, &self.lease_tx).await;
            owner.replica_sources.stop_all();
            return;
        };
        self.follow_type_cap().await;
        if self.reindex.swap(false, Ordering::SeqCst) {
            owner.last_index_ms = 0;
        }
        self.ensure_listeners(&mut owner, &stores);
        self.reconcile_replica_sources(&mut owner, &stores, &config);
        self.maintain_shards(&mut owner, &stores, &config).await;

        let lease = match &stores.backend {
            None => Some(WriterLease {
                fence: 0,
                expires_at_ms: now_ms() + OWNER_LEASE_TTL.as_millis() as u64,
            }),
            Some(backend) => {
                if owner
                    .lease_backend
                    .as_ref()
                    .is_some_and(|held| !same_backend(held, backend))
                {
                    step_down(&mut owner, &self.lease_tx).await;
                }
                let held = crate::runtime::reapers::reaper_leadership::maintain_leadership(
                    OWNER_ROLE,
                    backend.as_ref(),
                    OWNER_LEASE_TTL,
                    &mut owner.lease,
                )
                .await;
                if held {
                    owner.lease_backend = Some(Arc::clone(backend));
                    owner.lease.as_ref().map(writer_lease)
                } else {
                    None
                }
            }
        };
        let Some(lease) = lease else {
            if owner.owner {
                tracing::info!("this replica is no longer the events owner");
                owner.last_index_ms = 0;
            }
            owner.owner = false;
            owner.sources.stop_all();
            self.lease_tx.send_replace(None);
            // Subscribe checks its limits against this replica's index, so
            // a replica that only serves requests keeps it current too.
            let now = now_ms();
            if now.saturating_sub(owner.last_index_ms) >= INDEX_RESYNC.as_millis() as u64 {
                let catalog = self.catalog.load_full();
                if self.rebuild_index(&stores, &catalog).await {
                    owner.last_index_ms = now;
                    self.find_orphans(&stores, &catalog).await;
                }
            }
            return;
        };
        self.lease_tx.send_replace(Some(lease));
        let now = now_ms();
        let became_owner = !owner.owner;
        owner.owner = true;
        let catalog = self.catalog.load_full();

        if (became_owner
            || now.saturating_sub(owner.last_index_ms) >= INDEX_RESYNC.as_millis() as u64)
            && self.rebuild_index(&stores, &catalog).await
        {
            owner.last_index_ms = now;
            self.find_orphans(&stores, &catalog).await;
        }

        let runtime = self.runtime().map(|r| r.load_full());
        let registry = runtime.as_ref().map(|r| r.plugin_registry_arc());
        let plan = runtime.as_deref().map(plan_of).unwrap_or_default();
        if plan.ingest_held {
            if !owner.ingest_held {
                tracing::info!("the plan's monthly event ingest is used: event sources wait");
                self.mark_replica_sources_held(&stores, &catalog, &plan, lease)
                    .await;
            }
            owner.sources.stop_all();
        } else if let Some(runtime) = runtime.as_deref() {
            if owner.ingest_held {
                tracing::info!("the plan's event ingest is back: event sources resume");
            }
            let ctx = SourceContext {
                log: Arc::clone(&stores.log),
                lease: self.lease_tx.subscribe(),
                registry: runtime.plugin_registry_arc(),
                fetcher: self.resource_fetcher(),
                max_payload_bytes: config.webhook.max_payload_bytes,
                inbox: None,
                core: Arc::downgrade(self),
                usage: runtime.tool_call_recorder.clone(),
                quota: runtime.cp_quota_status.clone(),
            };
            let index = self.index.read().clone();
            owner.sources.reconcile(
                &catalog,
                &|name| index.has_demand(name, now),
                &ctx,
                self.generation.load(Ordering::SeqCst),
                config.sources.linger_ms,
                now,
            );
        }
        owner.ingest_held = plan.ingest_held;

        if now.saturating_sub(owner.last_inbox_ms) >= INBOX_POLL.as_millis() as u64 {
            self.drain_inboxes(&stores, &catalog, registry.as_deref(), lease, &config)
                .await;
            owner.last_inbox_ms = now;
        }
        if now.saturating_sub(owner.last_retention_ms) >= RETENTION_INTERVAL.as_millis() as u64 {
            for ty in catalog.types() {
                if let Err(error) = stores
                    .log
                    .enforce_retention(&ty.source_key, &plan.retention(&ty.retention), lease)
                    .await
                {
                    tracing::warn!(event = %ty.name, error = %error, "event log retention pass failed");
                }
                if let (Ok(Some(head)), Ok(bounds)) = (
                    stores.log.head(&ty.source_key).await,
                    stores.log.bounds(&ty.source_key).await,
                ) {
                    let depth = (bounds.head + 1).saturating_sub(bounds.floor);
                    metrics::gauge!("mcpg_events_log_depth", "event" => ty.name.clone())
                        .set(depth as f64);
                    metrics::gauge!("mcpg_events_log_bytes", "event" => ty.name.clone())
                        .set(head.bytes as f64);
                }
            }
            owner.last_retention_ms = now;
        }
        if now.saturating_sub(owner.last_reap_ms) >= REAPER_INTERVAL.as_millis() as u64 {
            self.reap_subscriptions(&stores, now).await;
            owner.last_reap_ms = now;
        }
    }

    /// Drain the inbox of every inbound type now. Public so tests and the
    /// owner's nudge path can drive it.
    pub async fn drain_now(self: &Arc<Self>) {
        let config = self.config.load_full();
        let Some(stores) = self.stores.load_full() else {
            return;
        };
        let lease = *self.lease_tx.borrow();
        let Some(lease) = lease else {
            return;
        };
        let catalog = self.catalog.load_full();
        let registry = self.runtime().map(|r| r.load().plugin_registry_arc());
        self.drain_inboxes(&stores, &catalog, registry.as_deref(), lease, &config)
            .await;
    }

    async fn drain_inboxes(
        &self,
        stores: &EventsStores,
        catalog: &EventCatalog,
        registry: Option<&mcpg_plugin_host::PluginRegistry>,
        lease: WriterLease,
        config: &EventsConfig,
    ) {
        let plan = self.plan();
        let usage = self
            .runtime()
            .map(|runtime| runtime.load().tool_call_recorder.clone())
            .unwrap_or_default();
        for ty in catalog.types() {
            let fed_through_inbox = matches!(
                ty.source,
                SourceSpec::Inbound(_) | SourceSpec::Builtin(_) | SourceSpec::Federation { .. }
            ) || ty.source.runs_on_every_replica();
            if !fed_through_inbox {
                continue;
            }
            let shape_row = |row: InboxRow| {
                let ty = Arc::clone(ty);
                async move {
                    let raw = RawOccurrence {
                        event_id: row.event_id,
                        timestamp: row.timestamp,
                        data: row.data,
                        audience: row.audience,
                        arguments: row.arguments,
                        upstream_cursor: None,
                    };
                    match shape(&ty, raw, registry, config.webhook.max_payload_bytes).await {
                        Ok(occurrence) => Some(occurrence),
                        Err(error) => {
                            metrics::counter!(
                                "mcpg_events_payload_dropped_total",
                                "event" => ty.name.clone(),
                                "reason" => error.label()
                            )
                            .increment(1);
                            None
                        }
                    }
                }
            };
            let retention = plan.retention(&ty.retention);
            loop {
                let mut pass = super::log::InboxDrain::default();
                let drained = stores
                    .log
                    .drain_inbox(&ty.source_key, &retention, lease, &shape_row, &mut pass)
                    .await;
                meter_ingest(&usage, ty, pass.appended, pass.bytes);
                match drained {
                    Ok(()) if pass.consumed >= super::log::DRAIN_BATCH => {}
                    Ok(()) => break,
                    Err(error) => {
                        tracing::warn!(event = %ty.name, error = %error, "event inbox drain failed");
                        break;
                    }
                }
            }
        }
    }

    /// Rebuild the subscription index from the store. On a store error the
    /// previous view stays and `false` asks for another try.
    async fn rebuild_index(&self, stores: &EventsStores, catalog: &EventCatalog) -> bool {
        let mut fresh = SubscriptionIndex::default();
        for ty in catalog.types() {
            match stores.subscriptions.list_type(&ty.name).await {
                Ok(entries) => fresh.replace_type(&ty.name, entries),
                Err(error) => {
                    tracing::warn!(event = %ty.name, error = %error, "subscription index rebuild failed; keeping the previous view");
                    return false;
                }
            }
            match stores.leases.demand(&ty.name).await {
                Ok(Some(until)) => fresh.note_lease(&ty.name, until),
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(event = %ty.name, error = %error, "lease demand could not be read");
                }
            }
        }
        let mut index = self.index.write();
        fresh.keep_leases_of(&index);
        *index = fresh;
        true
    }

    /// Hand the dispatcher the subscriptions of every type the catalog no
    /// longer has; forget a removed type that has none left. Not while a
    /// federation's first import is pending: the type may still come.
    async fn find_orphans(&self, stores: &EventsStores, catalog: &EventCatalog) {
        if self.imports_pending.load(Ordering::SeqCst) {
            return;
        }
        let names = match stores.subscriptions.type_names().await {
            Ok(names) => names,
            Err(error) => {
                tracing::debug!(error = %error, "event type names could not be listed");
                return;
            }
        };
        for name in names.iter().filter(|n| catalog.get(n).is_none()) {
            match stores.subscriptions.list_type(name).await {
                Ok(entries) if entries.is_empty() => {
                    if let Err(error) = stores.subscriptions.forget_type_name(name).await {
                        tracing::debug!(error = %error, "a removed event type could not be forgotten");
                    }
                }
                Ok(entries) => self
                    .orphans
                    .lock()
                    .extend(entries.into_iter().map(|e| e.id)),
                Err(error) => {
                    tracing::debug!(error = %error, "subscriptions of a removed event type could not be listed");
                }
            }
        }
    }

    async fn reap_subscriptions(&self, stores: &EventsStores, now: u64) {
        let expired = self
            .index
            .read()
            .expired(now, RECORD_GRACE.as_millis() as u64);
        for (name, id) in expired {
            match stores.subscriptions.delete(&id).await {
                Ok(_) => {
                    self.index.write().remove(&name, &id);
                    metrics::counter!("mcpg_events_subscriptions_reaped_total").increment(1);
                }
                Err(error) => {
                    tracing::warn!(error = %error, "expired subscription could not be removed");
                }
            }
        }
    }

    fn resource_fetcher(&self) -> Option<ResourceFetcher> {
        let runtime = self.runtime()?;
        let runtime = runtime.load_full();
        Some(crate::runtime::util::build_watch_resource_fetcher(
            Arc::clone(&runtime.capability_registry),
            Arc::clone(&runtime.execution_dispatcher),
        ))
    }

    fn ensure_listeners(self: &Arc<Self>, owner: &mut OwnerState, stores: &Arc<EventsStores>) {
        let key = Arc::as_ptr(stores) as usize;
        if owner.listeners_for == Some(key) {
            return;
        }
        for listener in owner.listeners.drain(..) {
            listener.abort();
        }
        owner.listeners_for = Some(key);
        let Some(bus) = stores.bus.clone() else {
            return;
        };
        let weak = Arc::downgrade(self);
        let subscriptions = Arc::clone(&stores.subscriptions);
        owner.listeners.push(tokio::spawn(async move {
            let Some(mut hints) = subscriptions.hints().await else {
                return;
            };
            while let Some(hint) = hints.next().await {
                let Some(core) = weak.upgrade() else {
                    return;
                };
                core.note_subscription(&hint);
            }
        }));
        let weak = Arc::downgrade(self);
        owner.listeners.push(tokio::spawn(async move {
            let Ok(mut nudges) = bus.subscribe(super::log::INBOX_TOPIC, None).await else {
                return;
            };
            while nudges.next().await.is_some() {
                let Some(core) = weak.upgrade() else {
                    return;
                };
                core.inbox_nudge.notify_one();
            }
        }));
    }
}

/// What `events/list` describes of `catalog`.
fn listed(catalog: &EventCatalog) -> Vec<(String, String)> {
    catalog
        .types()
        .iter()
        .map(|ty| (ty.name.clone(), ty.descriptor_fingerprint.clone()))
        .collect()
}

/// `configured` with the imported types it can serve beside it, each
/// given its schema epoch. An imported type that cannot be served is left
/// out with a warning.
async fn with_imports(
    configured: &EventCatalog,
    imported: &super::catalog::ImportedEvents,
    config: &EventsConfig,
    stores: &EventsStores,
    callbacks: bool,
) -> anyhow::Result<EventCatalog> {
    let enabled = config.enabled_modes();
    let ctx = super::catalog::ImportContext {
        enabled: &enabled,
        keys: &stores.keys,
        callbacks,
    };
    let mut types = configured.compile_federated(&imported.types, &ctx);
    for ty in &mut types {
        ty.schema_epoch = stores
            .log
            .schema_epoch(&ty.name, &ty.input_schema, &ty.payload_schema)
            .await
            .map_err(|e| anyhow::anyhow!("imported event type `{}`: {e}", ty.name))?;
    }
    Ok(configured.with_types(types))
}

/// Put each change of `imports` in force until the config generation moves
/// on from `generation`. An import that cannot be put in force now is
/// retried, so a store that fails for a moment never drops a type.
async fn follow_imports(
    weak: Weak<EventsCore>,
    mut imports: watch::Receiver<FederatedEvents>,
    generation: u64,
) {
    while imports.changed().await.is_ok() {
        loop {
            let Some(core) = weak.upgrade() else {
                return;
            };
            let imported = imports.borrow_and_update().clone();
            match core.import(&imported, generation).await {
                Ok(true) => break,
                Ok(false) => return,
                Err(error) => {
                    tracing::warn!(error = %error, "imported event types could not be put in force; retrying");
                }
            }
            drop(core);
            tokio::time::sleep(IMPORT_RETRY).await;
        }
    }
}

/// The keyed hash an occurrence names its only recipient by, from that
/// principal's trust-qualified key.
pub(crate) fn audience_hash(keys: &EventsKeys, principal_key: &str) -> String {
    keys.key_hash("event-audience", principal_key.as_bytes())
}

fn same_backend(a: &Arc<dyn ClusterBackend>, b: &Arc<dyn ClusterBackend>) -> bool {
    std::ptr::addr_eq(Arc::as_ptr(a), Arc::as_ptr(b))
}

/// The fence and the end of a held coordinator lease.
fn writer_lease(lease: &BoxActiveLease) -> WriterLease {
    WriterLease {
        fence: lease.fencing_token(),
        expires_at_ms: chrono::DateTime::parse_from_rfc3339(&lease.expires_at())
            .map(|t| t.timestamp_millis().max(0) as u64)
            .unwrap_or_else(|_| now_ms() + OWNER_LEASE_TTL.as_millis() as u64),
    }
}

/// Where a replica starts looking for free shards, so replicas that start
/// together reach for different ones first.
fn shard_offset(node_id: &str) -> u32 {
    let digest = hmac_sha256::Hash::hash(node_id.as_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % DISPATCH_SHARDS
}

async fn step_down(owner: &mut OwnerState, lease_tx: &watch::Sender<Option<WriterLease>>) {
    owner.sources.stop_all();
    if let Some(lease) = owner.lease.take()
        && let Err(error) = lease.release().await
    {
        tracing::debug!(error = %error, "events owner lease release failed; it expires on its own");
    }
    owner.lease_backend = None;
    if owner.owner {
        tracing::info!("this replica stepped down as the events owner");
    }
    owner.owner = false;
    lease_tx.send_replace(None);
}

/// Fetch `url` once through the delivery client: any HTTP answer shows
/// callbacks are reachable from this replica.
pub(crate) async fn probe_egress(egress: Arc<SafeEgress>, url: String) -> bool {
    let outcome = match egress.check_url(&url) {
        Ok(checked) => egress
            .get(&checked, axum::http::HeaderMap::new())
            .await
            .map(|answer| answer.status.as_u16())
            .map_err(|error| error.kind().as_str()),
        Err(_) => Err("url_refused"),
    };
    let reachable = outcome.is_ok();
    metrics::gauge!("mcpg_events_egress_probe_ok").set(if reachable { 1.0 } else { 0.0 });
    match outcome {
        Ok(status) => tracing::info!(status, "events egress probe answered"),
        Err(reason) => tracing::warn!(
            reason,
            "events egress probe failed; webhook deliveries are unlikely to reach their callbacks"
        ),
    }
    reachable
}

async fn owner_loop(weak: Weak<EventsCore>) {
    let mut ticker = tokio::time::interval(OWNER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let nudged = {
            let Some(core) = weak.upgrade() else {
                return;
            };
            tokio::select! {
                _ = ticker.tick() => false,
                () = core.inbox_nudge.notified() => true,
            }
        };
        let Some(core) = weak.upgrade() else {
            return;
        };
        if nudged {
            core.drain_now().await;
        } else {
            core.owner_tick().await;
        }
    }
}

async fn dispatch_loop(weak: Weak<EventsCore>) {
    let mut ticker = tokio::time::interval(DISPATCH_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let Some(core) = weak.upgrade() else {
            return;
        };
        core.dispatch_tick().await;
    }
}

async fn resolve_stores(
    config: &AppConfig,
    runtime: &GatewayRuntime,
    keys: Arc<EventsKeys>,
    origin: StoreOrigin,
) -> anyhow::Result<EventsStores> {
    use mcpg_plugin_protocol::store::StoreRole;
    let events = &config.mcp.configurations.events;
    let backend = runtime.cluster_backend();
    let registry = runtime.plugin_registry_arc();
    let cipher = crate::app::build_state_cipher(&config.cluster)?;
    let tenant = config.cluster.tenant_segment.clone();
    // On a coordinator with bounded buckets (NATS) the log and the
    // subscriptions get a bucket of their own, so they cannot crowd out
    // sessions and the other capabilities.
    let subscription_kv = crate::app::resolve_capability_kv_named(
        events.store.as_ref(),
        "events.subscriptions",
        backend.as_ref(),
        &registry,
        StoreRole::Custom("event-subscription".to_owned()),
        EVENTS_BUCKET,
    )
    .await?;
    let subscription_kv =
        crate::app::wrap_tenant_kv(crate::app::wrap_state_kv(subscription_kv, &cipher), &tenant);
    let log_kv = crate::app::resolve_capability_kv_named(
        events.log_store.as_ref(),
        "events.log",
        backend.as_ref(),
        &registry,
        StoreRole::Custom("event-log".to_owned()),
        EVENTS_BUCKET,
    )
    .await?;
    let log_kv = crate::app::wrap_tenant_kv(crate::app::wrap_state_kv(log_kv, &cipher), &tenant);
    let bus = crate::app::resolve_capability_bus(None, "events", backend.as_ref()).await?;
    let bus = crate::app::wrap_tenant_bus(crate::app::wrap_state_bus(bus, &cipher), &tenant);
    let subscription_class = EventStoreClass::of(events.store.as_ref(), &config.cluster);
    let log_class = EventStoreClass::of(events.log_store.as_ref(), &config.cluster);
    let in_process = |class: EventStoreClass| {
        matches!(
            class,
            EventStoreClass::SingleNodeCoordinator
                | EventStoreClass::Memory
                | EventStoreClass::File
        )
    };
    if !keys.is_stable() {
        tracing::warn!(
            "MCP Events runs on a key of this process: event logs and cursors do not outlive it"
        );
    }
    Ok(EventsStores {
        log: Arc::new(EventLog::new(
            log_kv,
            Some(Arc::clone(&bus)),
            Arc::clone(&keys),
        )),
        subscriptions: Arc::new(SubscriptionStore::new(
            Arc::clone(&subscription_kv),
            Some(Arc::clone(&bus)),
            Arc::clone(&keys),
        )),
        leases: Arc::new(LeaseStore::new(
            Arc::clone(&subscription_kv),
            Some(Arc::clone(&bus)),
            Arc::clone(&keys),
        )),
        routes: Arc::new(super::upstream_webhook::RouteStore::new(subscription_kv)),
        keys,
        bus: Some(bus),
        backend,
        subscriptions_durable: subscription_class.is_durable(),
        in_process: in_process(subscription_class) && in_process(log_class),
        origin,
    })
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
