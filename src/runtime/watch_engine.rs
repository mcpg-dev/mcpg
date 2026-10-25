//! Resource watch engine — detects resource changes via poll, NATS,
//! Kafka, or webhook and fans out `notifications/resources/updated`
//! to subscribed sessions through the delivery bus.
//!
//! In a fleet the watcher of a URI runs on one replica, the holder of the
//! URI's watch shard ([`super::watch_shards`]), and fans out to every
//! subscriber row whichever replica serves the subscriber. The holder learns
//! of subscribers on other replicas from the demand markers of the
//! subscription store: at once from a nudge on the watch bus, and within
//! [`MAINTAIN_TICK`] from the collector's listing. A poll watcher keeps its
//! last hash in the store, so the next holder of a shard tells of a change
//! made while the shard moved.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use mcpg_cluster_api::{ClusterBackend, PubSub};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::watch_shards::{ShardLeases, ShardSet, shard_of};
use crate::config::NotificationFilterConfig;
use crate::protocol::{JSONRPC_VERSION, ResourceUpdatedNotification, ResourceUpdatedParams};
use crate::runtime::pipeline_store::{DeliveryKind, DeliveryMessage};
use crate::runtime::subscription_store::{SubscriberIdentity, SubscriptionStore, WatchState};
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::{WatchEvent, WatchEventSink};

/// Interval of the collector: this member's liveness, the shard leases and
/// the demand listing.
pub const MAINTAIN_TICK: Duration = Duration::from_secs(5);
/// A member that has not marked itself alive for this long has left.
const MEMBER_TTL: Duration = Duration::from_secs(20);
/// Interval at which the collector removes the rows of subscribers that are
/// gone. A row is removed on the second pass that finds it gone.
pub(crate) const COLLECT_INTERVAL: Duration = Duration::from_secs(60);
/// Rows one collection pass reads, and sessions it checks, at most.
const COLLECT_ROW_BUDGET: usize = 50_000;
const COLLECT_SESSION_BUDGET: usize = 5_000;
/// Sweeper passes between two demand backfills, the first pass included:
/// the backfill reads every row of the fleet.
const BACKFILL_EVERY: u32 = 10;
/// How long the control loop waits on the store for one demand check.
const DEMAND_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a shutdown waits for the shards to be given back.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
/// A poll watcher writes its baseline again after this long without a
/// change, so the baseline outlives a resource that does not change.
const BASELINE_REFRESH: Duration = Duration::from_secs(3600);
/// Bus topic of demand nudges; the payload is the URI.
pub const DEMAND_TOPIC: &str = "mcpg.watch.demand";
/// How long a subscribed URI that no config watches waits before its
/// config is looked up again: a federation import or a reload can add one.
const UNWATCHED_RECHECK: Duration = Duration::from_secs(60);

/// Whether a session is still in use anywhere in the fleet, as
/// `SessionStore::session_alive` answers it.
pub type SessionLiveness = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

/// Called when this member finds itself gone from the store, so its holders
/// write their rows again.
pub type RejoinHook = Arc<dyn Fn() + Send + Sync>;

/// What the engine shares the watchers of the fleet through.
#[derive(Clone, Default)]
pub struct WatchCluster {
    /// The coordinator the shard leases are taken on; `None` holds every
    /// shard.
    pub backend: Option<Arc<dyn ClusterBackend>>,
    /// The bus demand nudges travel on; `None` leaves the holder of a shard
    /// to the collector's listing.
    pub bus: Option<Arc<dyn PubSub>>,
    pub tenant_segment: Option<String>,
    /// Lets the collector remove the rows of sessions that ended; `None`
    /// keeps them.
    pub session_alive: Option<SessionLiveness>,
}

impl std::fmt::Debug for WatchCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchCluster")
            .field(
                "backend",
                &self.backend.as_ref().map(|b| b.manifest().id.clone()),
            )
            .field("bus", &self.bus.is_some())
            .field("tenant_segment", &self.tenant_segment)
            .field("session_alive", &self.session_alive.is_some())
            .finish()
    }
}

/// Configuration for a resource watch.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub uri: String,
    pub strategy: WatchStrategy,
    /// Notification filter — controls which subscribers receive the notification.
    pub notification_filter: Option<NotificationFilterConfig>,
    /// Pre-compiled CEL program for `Expression` filter scope.
    pub compiled_filter_program: Option<Arc<cel::Program>>,
}

/// How the watch engine detects changes.
///
/// Poll and Webhook strategies are implemented in-engine. Transport-specific
/// strategies (NATS subject, Kafka topic, …) live in plugin crates and are
/// addressed via the `Plugin { kind, spec }` variant, which dispatches to a
/// `WatchStrategyPlugin` looked up on the plugin registry by `kind`.
#[derive(Debug, Clone)]
pub enum WatchStrategy {
    /// Periodically re-fetch the resource and compare hashes.
    Poll { interval_ms: u64 },
    /// Externally triggered via webhook — the engine registers a token and
    /// the HTTP handler calls `WatchCommand::ExternalNotify` when a POST
    /// arrives on `/webhooks/resource-updated/{token}`.
    Webhook {
        token: String,
        /// Superseded tokens still accepted, so a rotation does not drop
        /// events while senders are re-registered.
        previous_tokens: Vec<String>,
    },
    /// Delegate to a `WatchStrategyPlugin` looked up by `kind` (e.g.
    /// `"nats_topic"`, `"kafka_topic"`). The `spec` is passed verbatim
    /// to the plugin's `watch(...)` call.
    Plugin {
        kind: String,
        spec: serde_json::Value,
    },
}

/// Handle for a running watcher (used to cancel it).
#[derive(Debug)]
struct WatchHandle {
    cancel: CancellationToken,
    strategy: &'static str,
}

/// One running watcher, as reported by the admin API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WatchSnapshot {
    pub uri: String,
    pub strategy: &'static str,
    /// Subscribers of the URI this replica serves; the watcher tells the
    /// subscribers of every replica.
    pub subscriber_count: usize,
    /// The watch shard of the URI, which this replica holds.
    pub shard: u32,
}

/// Resolves a subscribed URI with no static `watch:` config to a
/// synthesized [`WatchConfig`] — the federated-resource hook: a
/// federated URI whose upstream cannot push `resources/updated` gets a
/// poll watcher manufactured on first subscribe. `None` keeps today's
/// ignore behavior.
pub type WatchProbe = Arc<dyn Fn(&str) -> Option<WatchConfig> + Send + Sync>;

/// Channel message to communicate with the watch engine control loop.
enum WatchCommand {
    /// A session on this replica subscribed to a resource URI.
    Subscribe { uri: String },
    /// A session on this replica unsubscribed from a resource URI.
    Unsubscribe { uri: String },
    /// A subscribe or unsubscribe on another replica may have changed the
    /// demand for `uri`.
    Nudge { uri: String },
    /// The demand markers the collector listed, from `listed_at`.
    Demand {
        uris: HashSet<String>,
        listed_at: Instant,
    },
    /// Share the watchers with the fleet.
    Attach(Box<WatchCluster>),
    /// This member was gone from the store; its holders write their rows
    /// again.
    Rejoined,
    /// External notification that a resource changed (webhook / admin API).
    ExternalNotify { uri: String },
    /// Report how many watchers are running.
    CountWatchers {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    /// Report every running watcher, for the admin API.
    ListWatchers {
        reply: tokio::sync::oneshot::Sender<Vec<WatchSnapshot>>,
    },
    /// Report the watch shards this replica holds.
    OwnedShards {
        reply: tokio::sync::oneshot::Sender<Vec<u32>>,
    },
    /// Shut down all watchers and give the shards back; `done` fires once
    /// they are.
    Shutdown {
        done: tokio::sync::oneshot::Sender<()>,
    },
}

/// The watch engine manages background watchers for subscribed resources.
///
/// It runs a watcher while a URI whose shard this replica holds has a
/// subscriber anywhere in the fleet. Change detection depends on the
/// `WatchStrategy` configured for each resource binding.
///
/// For multi-instance deployments, the delivery happens through the shared
/// `DeliveryBus` (NATS / Redis pub/sub), so notifications reach all instances.
#[derive(Clone)]
pub struct WatchEngine {
    command_tx: mpsc::Sender<WatchCommand>,
    /// Reverse map: webhook token → resource URI (for inbound webhook routing).
    webhook_tokens: Arc<HashMap<String, String>>,
    /// This engine's member id: the holder named in the rows of the
    /// subscriptions its streams hold. `None` for an engine that runs no
    /// collector, which keeps no member alive.
    member: Option<Arc<str>>,
    rejoin: Arc<OnceLock<RejoinHook>>,
}

impl std::fmt::Debug for WatchEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchEngine")
            .field("member", &self.member)
            .field("webhook_tokens", &self.webhook_tokens.len())
            .finish()
    }
}

impl WatchEngine {
    /// Start the watch engine background task.
    pub fn start(
        watch_configs: HashMap<String, WatchConfig>,
        subscription_store: Arc<dyn SubscriptionStore>,
        delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
        resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
    ) -> Self {
        Self::start_with_plugins(
            watch_configs,
            subscription_store,
            delivery_publish,
            resource_fetcher,
            None,
            None,
        )
    }

    /// Start with an optional plugin registry so `WatchStrategy::Plugin`
    /// variants can dispatch to a registered [`WatchStrategyPlugin`],
    /// and an optional [`WatchProbe`] that synthesizes configs for
    /// subscribed URIs with no static `watch:` block (federated
    /// resources). Back-compat shim `start` passes `None` for both.
    pub fn start_with_plugins(
        watch_configs: HashMap<String, WatchConfig>,
        subscription_store: Arc<dyn SubscriptionStore>,
        delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
        resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
        plugin_registry: Option<Arc<PluginRegistry>>,
        watch_probe: Option<WatchProbe>,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::channel(128);

        // Build the webhook token → URI reverse map. A superseded token routes
        // exactly like the live one until the operator drops it.
        let mut tokens: HashMap<String, String> = HashMap::new();
        for (uri, config) in &watch_configs {
            if let WatchStrategy::Webhook {
                token,
                previous_tokens,
            } = &config.strategy
            {
                for candidate in std::iter::once(token).chain(previous_tokens) {
                    if let Some(claimed) = tokens.insert(candidate.clone(), uri.clone())
                        && claimed != *uri
                    {
                        // Silently remapping one resource's webhook onto
                        // another is worse than either outcome, so say so.
                        warn!(
                            claimed_by = %claimed,
                            now = %uri,
                            "watch: webhook token is claimed by two resources; the later one wins"
                        );
                    }
                }
            }
        }

        // The control loop needs a reactor. Runtime construction in
        // synchronous test contexts has none — degrade to an inert
        // engine there (the dropped receiver makes every notify a
        // no-op), keeping the webhook map for sync resolution.
        let rejoin: Arc<OnceLock<RejoinHook>> = Arc::new(OnceLock::new());
        let member = match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let member: Arc<str> = Arc::from(uuid::Uuid::new_v4().simple().to_string());
                let state = subscription_store.watch_state();
                let shards = Arc::new(ShardSet::all());
                let collector_cancel = CancellationToken::new();
                let (cluster_tx, cluster_rx) = tokio::sync::watch::channel(None);
                let collector = state.clone().map(|state| {
                    handle.spawn(run_collector(
                        Collector::new(
                            state,
                            Arc::clone(&member),
                            Arc::clone(&shards),
                            command_tx.downgrade(),
                        ),
                        cluster_rx,
                        collector_cancel.clone(),
                    ))
                });
                let member = collector.as_ref().map(|_| member);
                let engine = EngineLoop {
                    configs: watch_configs,
                    probe: watch_probe,
                    ctx: WatchContext {
                        subscription_store,
                        delivery_publish,
                        resource_fetcher,
                        plugin_registry,
                        shards,
                        state,
                    },
                    active: HashMap::new(),
                    local: HashMap::new(),
                    demanded: HashSet::new(),
                    checked: HashMap::new(),
                    unwatched: HashMap::new(),
                    bus: None,
                    cluster_tx,
                    collector,
                    collector_cancel,
                    rejoin: Arc::clone(&rejoin),
                };
                handle.spawn(engine.run(command_rx));
                member
            }
            Err(_) => {
                drop(command_rx);
                None
            }
        };

        Self {
            command_tx,
            webhook_tokens: Arc::new(tokens),
            member,
            rejoin,
        }
    }

    /// Create a no-op engine (when no resource watches are configured).
    pub fn noop() -> Self {
        let (command_tx, _) = mpsc::channel(1);
        Self {
            command_tx,
            webhook_tokens: Arc::new(HashMap::new()),
            member: None,
            rejoin: Arc::new(OnceLock::new()),
        }
    }

    /// The holder this engine's streams name in their subscription rows;
    /// `None` when no collector keeps it alive.
    pub fn member_id(&self) -> Option<&str> {
        self.member.as_deref()
    }

    /// Run `hook` whenever this member finds itself gone from the store.
    /// The first hook set stays.
    pub fn on_rejoin(&self, hook: RejoinHook) {
        let _ = self.rejoin.set(hook);
    }

    /// Share the watchers with the fleet through `cluster`.
    pub async fn attach_cluster(&self, cluster: WatchCluster) {
        let _ = self
            .command_tx
            .send(WatchCommand::Attach(Box::new(cluster)))
            .await;
    }

    /// Notify the engine that a session subscribed to a URI.
    pub async fn notify_subscribe(&self, uri: &str) {
        let _ = self
            .command_tx
            .send(WatchCommand::Subscribe {
                uri: uri.to_owned(),
            })
            .await;
    }

    /// Notify the engine that a session unsubscribed from a URI.
    pub async fn notify_unsubscribe(&self, uri: &str) {
        let _ = self
            .command_tx
            .send(WatchCommand::Unsubscribe {
                uri: uri.to_owned(),
            })
            .await;
    }

    /// How many resource watchers are currently running.
    ///
    /// One per watched URI, regardless of how many sessions subscribe to it.
    /// `0` for an inert engine (no reactor at construction) and for one that
    /// has shut down.
    pub async fn active_watch_count(&self) -> usize {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(WatchCommand::CountWatchers { reply })
            .await
            .is_err()
        {
            return 0;
        }
        answer.await.unwrap_or(0)
    }

    /// Every running watcher, ordered by URI. Empty once the engine has shut
    /// down, which is indistinguishable from "nothing subscribed" — both mean
    /// no watcher is running.
    pub async fn list_watches(&self) -> Vec<WatchSnapshot> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(WatchCommand::ListWatchers { reply })
            .await
            .is_err()
        {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }

    /// The watch shards this replica holds, in order. Empty once the engine
    /// has shut down.
    pub async fn owned_shards(&self) -> Vec<u32> {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(WatchCommand::OwnedShards { reply })
            .await
            .is_err()
        {
            return Vec::new();
        }
        answer.await.unwrap_or_default()
    }

    /// Externally notify that a resource has changed (webhook / admin).
    pub async fn notify_resource_changed(&self, uri: &str) {
        let _ = self
            .command_tx
            .send(WatchCommand::ExternalNotify {
                uri: uri.to_owned(),
            })
            .await;
    }

    /// Resolve a webhook token to a resource URI (for the HTTP handler).
    pub fn resolve_webhook_token(&self, token: &str) -> Option<&String> {
        self.webhook_tokens.get(token)
    }

    /// Returns the webhook token map (for listing registered webhooks).
    pub fn webhook_tokens(&self) -> &HashMap<String, String> {
        &self.webhook_tokens
    }

    /// Shut down the engine and all active watchers, and give the shards
    /// back so other replicas take them at once.
    pub async fn shutdown(&self) {
        let (done, released) = tokio::sync::oneshot::channel();
        if self
            .command_tx
            .send(WatchCommand::Shutdown { done })
            .await
            .is_ok()
        {
            let _ = released.await;
        }
    }
}

/// What every watcher of an engine shares.
#[derive(Clone)]
struct WatchContext {
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
    plugin_registry: Option<Arc<PluginRegistry>>,
    /// A watcher tells of a change only while this replica holds its URI's
    /// shard.
    shards: Arc<ShardSet>,
    state: Option<WatchState>,
}

/// The control loop: one task owns the watcher table, so starting and
/// stopping a watcher never races another command.
struct EngineLoop {
    configs: HashMap<String, WatchConfig>,
    probe: Option<WatchProbe>,
    ctx: WatchContext,
    active: HashMap<String, WatchHandle>,
    /// Holders on this replica, per URI.
    local: HashMap<String, usize>,
    /// URIs with a demand marker, as last seen.
    demanded: HashSet<String>,
    /// Targeted demand checks newer than the last listing: when each
    /// started, and whether the marker was there.
    checked: HashMap<String, (Instant, bool)>,
    /// Demanded URIs no config watches, and when that was found: the probe
    /// runs again after [`UNWATCHED_RECHECK`], or on a subscribe here.
    unwatched: HashMap<String, Instant>,
    bus: Option<Arc<dyn PubSub>>,
    cluster_tx: tokio::sync::watch::Sender<Option<Arc<WatchCluster>>>,
    collector: Option<tokio::task::JoinHandle<()>>,
    collector_cancel: CancellationToken,
    rejoin: Arc<OnceLock<RejoinHook>>,
}

impl EngineLoop {
    async fn run(mut self, mut command_rx: mpsc::Receiver<WatchCommand>) {
        let mut done = None;
        while let Some(command) = command_rx.recv().await {
            match command {
                WatchCommand::Subscribe { uri } => self.subscribe(uri),
                WatchCommand::Unsubscribe { uri } => self.unsubscribe(uri).await,
                WatchCommand::Nudge { uri } => {
                    // Only the holder of the URI's shard acts on its demand.
                    if self.ctx.shards.owns_uri(&uri) {
                        self.check_demand(&uri).await;
                        self.reconcile(&uri);
                    }
                }
                WatchCommand::Demand { uris, listed_at } => self.listed(uris, listed_at),
                WatchCommand::Attach(cluster) => {
                    self.bus = cluster.bus.clone();
                    let _ = self.cluster_tx.send(Some(Arc::new(*cluster)));
                }
                WatchCommand::Rejoined => {
                    if let Some(hook) = self.rejoin.get() {
                        hook();
                    }
                }
                WatchCommand::ExternalNotify { uri } => self.external_notify(&uri),
                WatchCommand::CountWatchers { reply } => {
                    let _ = reply.send(self.active.len());
                }
                WatchCommand::ListWatchers { reply } => {
                    let _ = reply.send(self.snapshot());
                }
                WatchCommand::OwnedShards { reply } => {
                    let _ = reply.send(self.ctx.shards.owned());
                }
                WatchCommand::Shutdown { done: reply } => {
                    done = Some(reply);
                    break;
                }
            }
        }

        // A collector blocked on a full channel sees it closed, so it reaches
        // its cancellation and gives the shards back.
        drop(command_rx);

        // Cancel on EVERY exit, not just the `Shutdown` command: the loop also
        // ends when its last sender drops (a retired runtime), and a
        // `CancellationToken` does not cancel when dropped — so exiting without
        // this would leave every spawned watcher polling its resource until the
        // process ends.
        for (uri, handle) in self.active.drain() {
            handle.cancel.cancel();
            debug!(uri = %uri, "watch: watcher cancelled");
        }
        self.collector_cancel.cancel();
        if let Some(done) = done {
            if let Some(collector) = self.collector.take() {
                let _ = tokio::time::timeout(RELEASE_TIMEOUT, collector).await;
            }
            let _ = done.send(());
        }
    }

    fn subscribe(&mut self, uri: String) {
        *self.local.entry(uri.clone()).or_default() += 1;
        self.unwatched.remove(&uri);
        if self.ctx.shards.owns_uri(&uri) {
            self.reconcile(&uri);
        } else {
            // The store wrote the marker before this command was sent; the
            // holder of the shard reads it on the nudge.
            self.nudge(&uri);
        }
    }

    async fn unsubscribe(&mut self, uri: String) {
        let Some(count) = self.local.get_mut(&uri) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count > 0 {
            return;
        }
        self.local.remove(&uri);
        if self.ctx.shards.owns_uri(&uri) {
            // Subscribers on other replicas keep the watcher up.
            self.check_demand(&uri).await;
            self.reconcile(&uri);
        } else {
            self.nudge(&uri);
        }
    }

    /// Read the demand marker of `uri` now. A failed read keeps what the
    /// loop knew: the next listing decides.
    async fn check_demand(&mut self, uri: &str) {
        let Some(state) = &self.ctx.state else {
            self.demanded.remove(uri);
            return;
        };
        let started = Instant::now();
        match tokio::time::timeout(DEMAND_CHECK_TIMEOUT, state.has_demand(uri)).await {
            Ok(Ok(present)) => {
                if present {
                    self.demanded.insert(uri.to_owned());
                } else {
                    self.demanded.remove(uri);
                }
                self.checked.insert(uri.to_owned(), (started, present));
            }
            Ok(Err(error)) => {
                debug!(uri = %uri, %error, "watch: demand check failed; the next listing decides");
            }
            Err(_) => debug!(uri = %uri, "watch: demand check timed out; the next listing decides"),
        }
    }

    /// Take the collector's listing as the demand, except where a targeted
    /// check that started after the listing knows better.
    fn listed(&mut self, uris: HashSet<String>, listed_at: Instant) {
        let checked = &self.checked;
        let newer = |uri: &str| {
            checked
                .get(uri)
                .filter(|(at, _)| *at > listed_at)
                .map(|(_, present)| *present)
        };
        let mut demanded: HashSet<String> = uris
            .into_iter()
            .filter(|uri| newer(uri) != Some(false))
            .collect();
        demanded.extend(
            checked
                .iter()
                .filter(|(_, (at, present))| *present && *at > listed_at)
                .map(|(uri, _)| uri.clone()),
        );
        self.demanded = demanded;
        self.checked.retain(|_, (at, _)| *at > listed_at);
        self.unwatched.retain(|uri, _| self.demanded.contains(uri));
        metrics::gauge!("mcpg_watch_demanded_uris").set(self.demanded.len() as f64);
        self.reconcile_all();
    }

    fn reconcile_all(&mut self) {
        let uris: HashSet<String> = self
            .active
            .keys()
            .chain(self.demanded.iter())
            .chain(self.local.keys())
            .cloned()
            .collect();
        for uri in uris {
            self.reconcile(&uri);
        }
    }

    /// Start or stop the watcher of `uri`: it runs while this replica holds
    /// the URI's shard and the URI has a subscriber anywhere.
    fn reconcile(&mut self, uri: &str) {
        let owned = self.ctx.shards.owns_uri(uri);
        let wanted = owned && (self.local.contains_key(uri) || self.demanded.contains(uri));
        if wanted && !self.active.contains_key(uri) {
            self.start(uri);
        } else if !wanted && let Some(handle) = self.active.remove(uri) {
            handle.cancel.cancel();
            metrics::gauge!("mcpg_watch_active_watchers").set(self.active.len() as f64);
            if owned {
                // No subscriber is left: a later watcher of the URI starts
                // from what it reads then.
                if handle.strategy == "poll" {
                    self.clear_baseline(uri);
                }
                info!(uri = %uri, "watch: watcher stopped (no subscribers)");
            } else {
                info!(uri = %uri, "watch: watcher stopped (its shard moved to another replica)");
            }
        }
    }

    fn start(&mut self, uri: &str) {
        if self
            .unwatched
            .get(uri)
            .is_some_and(|at| at.elapsed() < UNWATCHED_RECHECK)
        {
            return;
        }
        let Some(config) = self
            .configs
            .get(uri)
            .cloned()
            .or_else(|| self.probe.as_ref().and_then(|probe| probe(uri)))
        else {
            if self
                .unwatched
                .insert(uri.to_owned(), Instant::now())
                .is_none()
            {
                debug!(uri = %uri, "watch: no config for resource, nothing to watch");
            }
            return;
        };
        self.unwatched.remove(uri);
        let cancel = CancellationToken::new();
        let strategy = strategy_name(&config.strategy);
        tokio::spawn(run_watcher(
            uri.to_owned(),
            config.strategy,
            cancel.clone(),
            self.ctx.clone(),
            config.notification_filter,
            config.compiled_filter_program,
        ));
        self.active
            .insert(uri.to_owned(), WatchHandle { cancel, strategy });
        metrics::gauge!("mcpg_watch_active_watchers").set(self.active.len() as f64);
        metrics::counter!("mcpg_watch_watchers_started_total", "strategy" => strategy).increment(1);
        info!(uri = %uri, strategy, shard = shard_of(uri), "watch: watcher started");
    }

    fn clear_baseline(&self, uri: &str) {
        let Some(state) = self.ctx.state.clone() else {
            return;
        };
        let uri = uri.to_owned();
        tokio::spawn(async move {
            if let Err(error) = state.clear_baseline(&uri).await {
                debug!(uri = %uri, %error, "watch: poll baseline not cleared; it expires on its own");
            }
        });
    }

    /// Tell the holder of `uri`'s shard that its demand may have changed.
    fn nudge(&self, uri: &str) {
        let Some(bus) = self.bus.clone() else {
            return;
        };
        let payload = Bytes::from(uri.to_owned());
        tokio::spawn(async move {
            if let Err(error) = bus.publish(DEMAND_TOPIC, payload).await {
                debug!(%error, "watch: demand nudge not published; the holder's listing finds it");
            }
        });
    }

    fn external_notify(&self, uri: &str) {
        // Directly fan out notifications to subscribers, respecting the filter.
        let (filter, compiled) = self
            .configs
            .get(uri)
            .and_then(|c| {
                c.notification_filter
                    .as_ref()
                    .map(|f| (Some(f), c.compiled_filter_program.as_deref()))
            })
            .unwrap_or((None, None));
        let count = notify_subscribers_filtered(
            uri,
            &*self.ctx.subscription_store,
            &*self.ctx.delivery_publish,
            filter,
            compiled,
            &EventContext::default(),
        );
        let strategy = self
            .active
            .get(uri)
            .map(|h| h.strategy)
            .unwrap_or("external");
        metrics::counter!("mcpg_watch_fired_total", "strategy" => strategy).increment(1);
        metrics::counter!("mcpg_watch_notifications_sent_total", "strategy" => strategy)
            .increment(count as u64);
        if count > 0 {
            info!(uri = %uri, subscriber_count = count, "watch: external notify delivered");
        } else {
            debug!(uri = %uri, "watch: external notify but no subscribers");
        }
        // Emit an audit event: the webhook watch strategy fired.
        if let Some(registry) = self.ctx.plugin_registry.clone() {
            let uri_owned = uri.to_owned();
            let count_u64 = count as u64;
            tokio::spawn(async move {
                let event = mcpg_plugin_host::audit_events::watch_fired_event(
                    &uri_owned, "webhook", None, count_u64,
                );
                let _ = registry.emit_audit_event(&event).await;
            });
        }
    }

    fn snapshot(&self) -> Vec<WatchSnapshot> {
        let mut snapshot: Vec<WatchSnapshot> = self
            .active
            .iter()
            .map(|(uri, handle)| WatchSnapshot {
                uri: uri.clone(),
                strategy: handle.strategy,
                subscriber_count: self.local.get(uri).copied().unwrap_or(0),
                shard: shard_of(uri),
            })
            .collect();
        // Stable order: the admin API is read by humans and by diffing
        // scripts, and a HashMap iteration order is neither.
        snapshot.sort_by(|a, b| a.uri.cmp(&b.uri));
        snapshot
    }
}

/// Keeps this member alive in the store, holds its share of the shards,
/// lists the demand for the control loop, and runs the sweeper. It starts
/// when the runtime attaches the fleet ([`WatchEngine::attach_cluster`]).
struct Collector {
    state: WatchState,
    member: Arc<str>,
    shards: Arc<ShardSet>,
    commands: mpsc::WeakSender<WatchCommand>,
    leases: Option<ShardLeases>,
    nudges: Option<tokio::task::JoinHandle<()>>,
    bus: Option<Arc<dyn PubSub>>,
    sweeper: Option<tokio::task::JoinHandle<()>>,
    sweeper_cancel: CancellationToken,
    /// The live members as the last pass read them, for the sweeper; `None`
    /// when that read failed.
    live_tx: tokio::sync::watch::Sender<Option<Arc<HashSet<String>>>>,
    /// Whether this member has marked itself alive since it started.
    joined: bool,
    members: usize,
}

impl Collector {
    fn new(
        state: WatchState,
        member: Arc<str>,
        shards: Arc<ShardSet>,
        commands: mpsc::WeakSender<WatchCommand>,
    ) -> Self {
        Self {
            state,
            member,
            shards,
            commands,
            leases: None,
            nudges: None,
            bus: None,
            sweeper: None,
            sweeper_cancel: CancellationToken::new(),
            live_tx: tokio::sync::watch::channel(None).0,
            joined: false,
            members: 1,
        }
    }

    async fn attach(&mut self, cluster: Arc<WatchCluster>) {
        let same_backend = match (&self.leases, &cluster.backend) {
            (Some(leases), Some(backend)) => {
                std::ptr::addr_eq(Arc::as_ptr(leases.backend()), Arc::as_ptr(backend))
            }
            _ => false,
        };
        if !same_backend {
            if let Some(mut leases) = self.leases.take() {
                leases.release_all().await;
            }
            match &cluster.backend {
                Some(backend) => {
                    self.leases = Some(ShardLeases::new(
                        Arc::clone(backend),
                        cluster.tenant_segment.as_deref(),
                        Arc::clone(&self.shards),
                    ));
                }
                None => self.shards.hold_all(),
            }
        }
        self.bus = cluster.bus.clone();
        self.listen_for_nudges().await;

        self.sweeper_cancel.cancel();
        if let Some(sweeper) = self.sweeper.take() {
            sweeper.abort();
        }
        self.sweeper_cancel = CancellationToken::new();
        self.sweeper = Some(tokio::spawn(run_sweeper(
            self.state.clone(),
            Arc::clone(&self.shards),
            self.live_tx.subscribe(),
            cluster.session_alive.clone(),
            self.sweeper_cancel.clone(),
        )));
    }

    async fn listen_for_nudges(&mut self) {
        if let Some(nudges) = self.nudges.take() {
            nudges.abort();
        }
        let Some(bus) = &self.bus else {
            return;
        };
        match bus.subscribe(DEMAND_TOPIC, None).await {
            Ok(stream) => {
                self.nudges = Some(tokio::spawn(forward_nudges(stream, self.commands.clone())));
            }
            Err(error) => warn!(
                %error,
                "watch: demand nudges unavailable; a shard holder finds new demand within the listing interval"
            ),
        }
    }

    async fn pass(&mut self) {
        self.beat().await;
        if let Some(leases) = &mut self.leases {
            leases.maintain(&self.member, self.members).await;
        }
        if self.bus.is_some() && self.nudges.as_ref().is_none_or(|n| n.is_finished()) {
            self.listen_for_nudges().await;
        }
        let listed_at = Instant::now();
        match self.state.demanded().await {
            Ok(uris) => {
                self.send(WatchCommand::Demand {
                    uris: uris.into_iter().collect(),
                    listed_at,
                })
                .await;
            }
            Err(error) => warn!(%error, "watch: demand listing failed; next pass"),
        }
    }

    async fn beat(&mut self) {
        let listed = match self.state.members().await {
            Ok(members) => Some(members.into_iter().collect::<HashSet<String>>()),
            Err(error) => {
                warn!(%error, "watch: member listing failed; next pass");
                None
            }
        };
        if self.joined
            && let Some(live) = &listed
            && !live.contains(&*self.member)
        {
            warn!(
                "watch: this replica was gone from the subscription store; its subscriptions are written again"
            );
            self.send(WatchCommand::Rejoined).await;
        }
        match self.state.beat(&self.member, MEMBER_TTL).await {
            Ok(()) => self.joined = true,
            Err(error) => warn!(%error, "watch: this replica could not mark itself alive"),
        }
        // Without a listing the share stays as it was, and the sweeper
        // waits rather than judge rows against an old view. This replica
        // counts itself whether or not its mark was written.
        let live = listed.map(|mut live| {
            live.insert(self.member.to_string());
            self.members = live.len();
            Arc::new(live)
        });
        metrics::gauge!("mcpg_watch_members").set(self.members as f64);
        self.live_tx.send_replace(live);
    }

    async fn send(&self, command: WatchCommand) {
        if let Some(commands) = self.commands.upgrade() {
            let _ = commands.send(command).await;
        }
    }

    /// Give the shards back and leave the members, so the other replicas
    /// take over at once rather than on expiry.
    async fn stop(&mut self) {
        self.sweeper_cancel.cancel();
        if let Some(sweeper) = self.sweeper.take() {
            sweeper.abort();
        }
        if let Some(nudges) = self.nudges.take() {
            nudges.abort();
        }
        if let Some(mut leases) = self.leases.take() {
            leases.release_all().await;
        }
        if self.joined
            && let Err(error) = self.state.leave(&self.member).await
        {
            debug!(%error, "watch: member not removed; it expires on its own");
        }
    }
}

async fn run_collector(
    mut collector: Collector,
    mut cluster_rx: tokio::sync::watch::Receiver<Option<Arc<WatchCluster>>>,
    cancel: CancellationToken,
) {
    // Nothing is shared before the runtime attaches the fleet: until then
    // this replica holds every shard and watches what its own sessions
    // subscribe to.
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            changed = cluster_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                let cluster = cluster_rx.borrow_and_update().clone();
                if let Some(cluster) = cluster {
                    collector.attach(cluster).await;
                    break;
                }
            }
        }
    }
    let mut tick = tokio::time::interval(MAINTAIN_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            changed = cluster_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let cluster = cluster_rx.borrow_and_update().clone();
                if let Some(cluster) = cluster {
                    collector.attach(cluster).await;
                }
                collector.pass().await;
            }
            _ = tick.tick() => collector.pass().await,
        }
    }
    collector.stop().await;
}

async fn forward_nudges(
    mut stream: mcpg_cluster_api::Subscription,
    commands: mpsc::WeakSender<WatchCommand>,
) {
    use futures::StreamExt as _;
    while let Some(message) = stream.next().await {
        let Ok(message) = message else {
            continue;
        };
        let Ok(uri) = String::from_utf8(message.payload.to_vec()) else {
            continue;
        };
        let Some(commands) = commands.upgrade() else {
            return;
        };
        if commands.send(WatchCommand::Nudge { uri }).await.is_err() {
            return;
        }
    }
}

/// Removes the rows of subscribers that are gone, on the shards this
/// replica holds: a row whose holder left the fleet, or whose session
/// ended. A row goes on the second pass that finds it gone, so one late
/// beat or one failed read does not drop a live subscription. A URI left
/// without rows loses its demand marker, which stops its watcher.
async fn run_sweeper(
    state: WatchState,
    shards: Arc<ShardSet>,
    live: tokio::sync::watch::Receiver<Option<Arc<HashSet<String>>>>,
    session_alive: Option<SessionLiveness>,
    cancel: CancellationToken,
) {
    let mut suspects = HashSet::new();
    let mut tick = tokio::time::interval(COLLECT_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick is immediate; the members need a pass to mark
    // themselves alive first.
    tick.tick().await;
    let mut passes: u32 = 0;
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        // One replica of the fleet, the holder of shard 0, backfills.
        if passes.is_multiple_of(BACKFILL_EVERY) && shards.owns(0) {
            match state.backfill_demand().await {
                Ok(0) => {}
                Ok(written) => info!(
                    written,
                    "watch: demand markers written for rows without one"
                ),
                Err(error) => debug!(%error, "watch: demand backfill failed; next time"),
            }
        }
        passes = passes.wrapping_add(1);
        let Some(members) = live.borrow().clone() else {
            continue;
        };
        suspects = sweep(&state, &shards, &members, session_alive.as_ref(), &suspects).await;
    }
}

/// One sweeper pass; returns the rows found gone that it kept.
async fn sweep(
    state: &WatchState,
    shards: &ShardSet,
    live: &HashSet<String>,
    session_alive: Option<&SessionLiveness>,
    suspects: &HashSet<(String, String)>,
) -> HashSet<(String, String)> {
    let uris = match state.demanded().await {
        Ok(uris) => uris,
        Err(error) => {
            warn!(%error, "watch: sweeper listing failed; next pass");
            return suspects.clone();
        }
    };
    let mut kept = HashSet::new();
    let mut rows_read = 0usize;
    let mut sessions_checked = 0usize;
    for uri in uris.into_iter().filter(|uri| shards.owns_uri(uri)) {
        if rows_read >= COLLECT_ROW_BUDGET {
            warn!(
                rows_read,
                "watch: sweeper stopped at its row budget; the remaining URIs wait for the next pass"
            );
            break;
        }
        let rows = match state.rows(&uri).await {
            Ok(rows) => rows,
            Err(error) => {
                debug!(uri = %uri, %error, "watch: sweeper could not read the rows of a URI");
                continue;
            }
        };
        rows_read += rows.len();
        let mut removed = 0usize;
        for row in &rows {
            let gone = match &row.holder {
                Some(holder) => !live.contains(holder),
                None => match session_alive {
                    Some(alive) if sessions_checked < COLLECT_SESSION_BUDGET => {
                        sessions_checked += 1;
                        alive(&row.session_id) == Some(false)
                    }
                    _ => false,
                },
            };
            if !gone {
                continue;
            }
            let key = (uri.clone(), row.session_id.clone());
            if !suspects.contains(&key) {
                kept.insert(key);
                continue;
            }
            match state.remove_row(&row.session_id, &uri).await {
                Ok(()) => {
                    removed += 1;
                    let reason = if row.holder.is_some() {
                        "holder_gone"
                    } else {
                        "session_ended"
                    };
                    metrics::counter!("mcpg_watch_rows_collected_total", "reason" => reason)
                        .increment(1);
                }
                Err(error) => {
                    debug!(uri = %uri, %error, "watch: sweeper could not remove a row; next pass");
                    kept.insert(key);
                }
            }
        }
        if removed == rows.len()
            && let Err(error) = state.drop_demand_if_unsubscribed(&uri).await
        {
            debug!(uri = %uri, %error, "watch: sweeper could not drop a demand marker; next pass");
        }
    }
    kept
}

/// Poll cadence for a poll watcher: the configured `interval_ms`
/// (milliseconds), floored at 10 seconds so a misconfigured watcher
/// cannot hammer a backend.
fn poll_interval(interval_ms: u64) -> tokio::time::Duration {
    tokio::time::Duration::from_millis(interval_ms.max(10_000))
}

#[cfg(test)]
mod interval_tests {
    use super::poll_interval;

    #[test]
    fn poll_interval_is_milliseconds_with_ten_second_floor() {
        assert_eq!(poll_interval(60_000).as_secs(), 60);
        assert_eq!(poll_interval(30_000).as_secs(), 30);
        assert_eq!(poll_interval(500).as_secs(), 10);
        assert_eq!(poll_interval(0).as_secs(), 10);
    }
}

fn strategy_name(s: &WatchStrategy) -> &'static str {
    match s {
        WatchStrategy::Poll { .. } => "poll",
        WatchStrategy::Webhook { .. } => "webhook",
        WatchStrategy::Plugin { .. } => "plugin",
    }
}

fn build_resource_updated_message(uri: &str) -> serde_json::Value {
    let notification = ResourceUpdatedNotification {
        jsonrpc: JSONRPC_VERSION,
        method: "notifications/resources/updated",
        params: ResourceUpdatedParams {
            uri: uri.to_owned(),
        },
    };
    serde_json::to_value(&notification).expect("resource notification serialized")
}

/// Context about the event that triggered a notification, used for
/// subject-scoped filtering. Currently carries an optional `user_id`
/// extracted from webhook/event payloads and the originating session.
#[derive(Debug, Clone, Default)]
pub struct EventContext {
    /// User/principal that caused the change (from webhook payload etc.).
    pub user_id: Option<String>,
    /// Session that triggered the change (if available).
    pub session_id: Option<String>,
}

fn notify_subscribers_filtered(
    uri: &str,
    subscription_store: &dyn SubscriptionStore,
    delivery_publish: &(dyn Fn(&str, DeliveryMessage) + Send + Sync),
    filter: Option<&NotificationFilterConfig>,
    compiled_program: Option<&cel::Program>,
    event_ctx: &EventContext,
) -> usize {
    // When no filter is configured, use the fast path (no identity lookup).
    let filter = match filter {
        Some(f) => f,
        None => {
            let subscribers = subscription_store.subscribers_for(uri);
            if subscribers.is_empty() {
                return 0;
            }
            let jsonrpc_message = build_resource_updated_message(uri);
            for session_id in &subscribers {
                let msg = DeliveryMessage {
                    kind: DeliveryKind::ResourceUpdated,
                    jsonrpc_message: jsonrpc_message.clone(),
                    delivery_id: String::new(),
                };
                delivery_publish(session_id, msg);
            }
            return subscribers.len();
        }
    };

    match filter {
        NotificationFilterConfig::All => {
            let subscribers = subscription_store.subscribers_for(uri);
            if subscribers.is_empty() {
                return 0;
            }
            let jsonrpc_message = build_resource_updated_message(uri);
            for session_id in &subscribers {
                let msg = DeliveryMessage {
                    kind: DeliveryKind::ResourceUpdated,
                    jsonrpc_message: jsonrpc_message.clone(),
                    delivery_id: String::new(),
                };
                delivery_publish(session_id, msg);
            }
            subscribers.len()
        }
        NotificationFilterConfig::SubjectId => {
            // If the event has no user context, fall back to fan-out.
            let event_user_id = match &event_ctx.user_id {
                Some(uid) => uid.clone(),
                None => {
                    let subscribers = subscription_store.subscribers_for(uri);
                    let jsonrpc_message = build_resource_updated_message(uri);
                    for session_id in &subscribers {
                        let msg = DeliveryMessage {
                            kind: DeliveryKind::ResourceUpdated,
                            jsonrpc_message: jsonrpc_message.clone(),
                            delivery_id: String::new(),
                        };
                        delivery_publish(session_id, msg);
                    }
                    return subscribers.len();
                }
            };

            let subscribers = subscription_store.subscribers_with_identity(uri);
            if subscribers.is_empty() {
                return 0;
            }
            let jsonrpc_message = build_resource_updated_message(uri);
            let mut count = 0;
            for (session_id, identity) in &subscribers {
                let matches = identity
                    .as_ref()
                    .and_then(|id| id.principal_id.as_deref())
                    .map(|pid| pid == event_user_id)
                    .unwrap_or(false);
                if matches {
                    let msg = DeliveryMessage {
                        kind: DeliveryKind::ResourceUpdated,
                        jsonrpc_message: jsonrpc_message.clone(),
                        delivery_id: String::new(),
                    };
                    delivery_publish(session_id, msg);
                    count += 1;
                }
            }
            count
        }
        NotificationFilterConfig::SessionId => {
            let originating_session = match &event_ctx.session_id {
                Some(sid) => sid.clone(),
                None => {
                    // No originating session — fall back to fan-out.
                    let subscribers = subscription_store.subscribers_for(uri);
                    let jsonrpc_message = build_resource_updated_message(uri);
                    for session_id in &subscribers {
                        let msg = DeliveryMessage {
                            kind: DeliveryKind::ResourceUpdated,
                            jsonrpc_message: jsonrpc_message.clone(),
                            delivery_id: String::new(),
                        };
                        delivery_publish(session_id, msg);
                    }
                    return subscribers.len();
                }
            };

            // Only deliver to the originating session if it is subscribed.
            let subscribers = subscription_store.subscribers_for(uri);
            if subscribers.contains(&originating_session) {
                let jsonrpc_message = build_resource_updated_message(uri);
                let msg = DeliveryMessage {
                    kind: DeliveryKind::ResourceUpdated,
                    jsonrpc_message,
                    delivery_id: String::new(),
                };
                delivery_publish(&originating_session, msg);
                1
            } else {
                0
            }
        }
        NotificationFilterConfig::Expression { .. } => {
            let program = match compiled_program {
                Some(p) => p,
                None => {
                    // Fails OPEN: every subscriber is notified, which is the
                    // one path here with a confidentiality consequence. The
                    // counter exists so it can be alerted on rather than
                    // noticed in a log.
                    metrics::counter!("mcpg_watch_filter_fallback_total").increment(1);
                    warn!(uri = %uri, "notification filter: CEL program not compiled, falling back to fan-out");
                    let subscribers = subscription_store.subscribers_for(uri);
                    let jsonrpc_message = build_resource_updated_message(uri);
                    for session_id in &subscribers {
                        let msg = DeliveryMessage {
                            kind: DeliveryKind::ResourceUpdated,
                            jsonrpc_message: jsonrpc_message.clone(),
                            delivery_id: String::new(),
                        };
                        delivery_publish(session_id, msg);
                    }
                    return subscribers.len();
                }
            };

            let subscribers = subscription_store.subscribers_with_identity(uri);
            if subscribers.is_empty() {
                return 0;
            }
            let jsonrpc_message = build_resource_updated_message(uri);
            let mut count = 0;
            for (session_id, identity) in &subscribers {
                let matches = evaluate_filter_expression(program, identity.as_ref(), uri);
                if matches {
                    let msg = DeliveryMessage {
                        kind: DeliveryKind::ResourceUpdated,
                        jsonrpc_message: jsonrpc_message.clone(),
                        delivery_id: String::new(),
                    };
                    delivery_publish(session_id, msg);
                    count += 1;
                }
            }
            count
        }
    }
}

/// Evaluate a compiled CEL filter expression against a subscriber's identity.
/// Returns `true` if the subscriber should receive the notification.
fn evaluate_filter_expression(
    program: &cel::Program,
    identity: Option<&SubscriberIdentity>,
    uri: &str,
) -> bool {
    use cel::{
        Context as CelContext, Value as CelValue,
        objects::{Key as CelKey, Map as CelMap},
    };

    let empty_identity = SubscriberIdentity::default();
    let id = identity.unwrap_or(&empty_identity);

    // Build `subscriber` map.
    let mut subscriber_map: HashMap<CelKey, CelValue> = HashMap::new();
    subscriber_map.insert(
        CelKey::String("principal_id".to_owned().into()),
        id.principal_id
            .as_ref()
            .map(|p| CelValue::String(p.clone().into()))
            .unwrap_or(CelValue::Null),
    );
    subscriber_map.insert(
        CelKey::String("trust_level".to_owned().into()),
        CelValue::String(id.trust_level.clone().into()),
    );
    subscriber_map.insert(
        CelKey::String("roles".to_owned().into()),
        CelValue::List(Arc::new(
            id.roles
                .iter()
                .map(|r| CelValue::String(r.clone().into()))
                .collect(),
        )),
    );
    subscriber_map.insert(
        CelKey::String("groups".to_owned().into()),
        CelValue::List(Arc::new(
            id.groups
                .iter()
                .map(|g| CelValue::String(g.clone().into()))
                .collect(),
        )),
    );
    subscriber_map.insert(
        CelKey::String("scopes".to_owned().into()),
        CelValue::List(Arc::new(
            id.scopes
                .iter()
                .map(|s| CelValue::String(s.clone().into()))
                .collect(),
        )),
    );
    let attr_map: HashMap<CelKey, CelValue> = id
        .attributes
        .iter()
        .map(|(k, v)| {
            (
                CelKey::String(k.clone().into()),
                CelValue::String(v.clone().into()),
            )
        })
        .collect();
    subscriber_map.insert(
        CelKey::String("attributes".to_owned().into()),
        CelValue::Map(CelMap {
            map: Arc::new(attr_map),
        }),
    );

    let subscriber_val = CelValue::Map(CelMap {
        map: Arc::new(subscriber_map),
    });

    // Build `event` map.
    let mut event_map: HashMap<CelKey, CelValue> = HashMap::new();
    event_map.insert(
        CelKey::String("uri".to_owned().into()),
        CelValue::String(uri.to_owned().into()),
    );
    let event_val = CelValue::Map(CelMap {
        map: Arc::new(event_map),
    });

    let mut ctx = CelContext::default();
    let _ = ctx.add_variable("subscriber", subscriber_val);
    let _ = ctx.add_variable("event", event_val);

    match program.execute(&ctx) {
        Ok(CelValue::Bool(b)) => b,
        Ok(_) => {
            warn!(
                "notification filter CEL expression did not return a boolean, defaulting to false"
            );
            false
        }
        Err(e) => {
            warn!(error = %e, "notification filter CEL expression evaluation failed, defaulting to false");
            false
        }
    }
}

/// Compile a CEL expression for notification filtering. Called once at config
/// load time so the program is not recompiled per-notification.
pub fn compile_notification_filter(expression: &str) -> Option<Arc<cel::Program>> {
    match cel::Program::compile(expression) {
        Ok(program) => Some(Arc::new(program)),
        Err(e) => {
            warn!(expression = %expression, error = %e, "failed to compile notification filter CEL expression");
            None
        }
    }
}

async fn run_watcher(
    uri: String,
    strategy: WatchStrategy,
    cancel: CancellationToken,
    ctx: WatchContext,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
) {
    match strategy {
        WatchStrategy::Poll { interval_ms } => {
            run_poll_watcher(
                uri,
                interval_ms,
                cancel,
                ctx,
                notification_filter,
                compiled_filter_program,
            )
            .await;
        }
        WatchStrategy::Webhook { .. } => {
            // Webhook watchers do nothing internally — notifications come through
            // WatchCommand::ExternalNotify triggered by the HTTP webhook handler.
            cancel.cancelled().await;
            debug!(uri = %uri, "webhook watcher cancelled");
        }
        WatchStrategy::Plugin { kind, spec } => {
            run_plugin_watcher(
                uri,
                kind,
                spec,
                cancel,
                ctx,
                notification_filter,
                compiled_filter_program,
            )
            .await;
        }
    }
}

/// Bridge from [`WatchStrategyPlugin`]-emitted [`WatchEvent`]s to the
/// gateway's subscription-aware fan-out. One sink per running
/// plugin watcher; the plugin calls `emit` on every observed change
/// and this implementation reuses [`notify_subscribers_filtered`] so
/// all the existing filter modes (All / SubjectId / SessionId /
/// Expression) keep working without duplication.
struct ResourceUpdatedSink {
    uri: String,
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
    plugin_kind: String,
    plugin_registry: Option<Arc<PluginRegistry>>,
    shards: Arc<ShardSet>,
    /// Positions of handled events, for the watcher to acknowledge.
    acks: mpsc::Sender<serde_json::Value>,
}

#[async_trait]
impl WatchEventSink for ResourceUpdatedSink {
    async fn emit(&self, event: WatchEvent) {
        // A replica that gave the shard up leaves the event to the new
        // holder, unacknowledged: an upstream that redelivers delivers it
        // there.
        if !self.shards.owns_uri(&self.uri) {
            return;
        }
        // A notification is told once and never retried, so the event is
        // handled as soon as it is fanned out. A full queue only delays the
        // acknowledgement to the upstream's redelivery.
        if let Some(position) = event.upstream_cursor {
            let _ = self.acks.try_send(position);
        }
        // A notification keeps no history, so a gap alone says nothing to
        // its subscribers.
        if event.gap && event.event_type.is_none() && event.data.is_none() {
            return;
        }
        let ctx = EventContext {
            user_id: event.user_id,
            session_id: event.session_id,
        };
        let count = notify_subscribers_filtered(
            &self.uri,
            &*self.subscription_store,
            &*self.delivery_publish,
            self.notification_filter.as_ref(),
            self.compiled_filter_program.as_deref(),
            &ctx,
        );
        if count > 0 {
            info!(
                uri = %self.uri,
                subscriber_count = count,
                "plugin watch: notifications delivered"
            );
        } else {
            debug!(uri = %self.uri, "plugin watch: no matching subscribers");
        }
        // Emit an audit event: the plugin watch strategy fired.
        if let Some(registry) = self.plugin_registry.clone() {
            let uri_owned = self.uri.clone();
            let plugin_kind = self.plugin_kind.clone();
            let count_u64 = count as u64;
            tokio::spawn(async move {
                let event = mcpg_plugin_host::audit_events::watch_fired_event(
                    &uri_owned,
                    "plugin",
                    Some(&plugin_kind),
                    count_u64,
                );
                let _ = registry.emit_audit_event(&event).await;
            });
        }
    }
}

/// Dispatch a `WatchStrategy::Plugin` watcher through a registered
/// [`WatchStrategyPlugin`]. Without a registry the watcher idles —
/// that matches the pre-registry behavior and makes tests that spin
/// up the engine without plugins continue to pass.
async fn run_plugin_watcher(
    uri: String,
    kind: String,
    spec: serde_json::Value,
    cancel: CancellationToken,
    ctx: WatchContext,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
) {
    let Some(registry) = ctx.plugin_registry.clone() else {
        debug!(
            uri = %uri,
            kind = %kind,
            "plugin watch: no plugin registry available — idling until cancelled"
        );
        cancel.cancelled().await;
        return;
    };
    let Some(plugin) = registry.watch_strategy(&kind) else {
        warn!(
            uri = %uri,
            kind = %kind,
            "plugin watch: no plugin registered for strategy — idling until cancelled"
        );
        cancel.cancelled().await;
        return;
    };

    let (acks, mut handled) = mpsc::channel(PLUGIN_ACK_CAPACITY);
    let sink = Arc::new(ResourceUpdatedSink {
        uri: uri.clone(),
        subscription_store: ctx.subscription_store,
        delivery_publish: ctx.delivery_publish,
        notification_filter,
        compiled_filter_program,
        plugin_kind: kind.clone(),
        plugin_registry: Some(registry.clone()),
        shards: ctx.shards,
        acks,
    });

    let handle = match plugin.watch(&uri, &spec, sink).await {
        Ok(h) => h,
        Err(e) => {
            warn!(
                uri = %uri,
                kind = %kind,
                error = %e,
                "plugin watch: plugin.watch() failed"
            );
            return;
        }
    };

    info!(uri = %uri, kind = %kind, "plugin watch: watcher started");
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            Some(position) = handled.recv() => handle.acknowledge(&position).await,
        }
    }
    handle.cancel().await;
    debug!(uri = %uri, kind = %kind, "plugin watch: watcher cancelled");
}

/// Positions a plugin watcher holds for acknowledgement; past it, an
/// acknowledgement waits for the upstream's redelivery.
const PLUGIN_ACK_CAPACITY: usize = 1024;

// ─── Poll Watcher ────────────────────────────────────────────────────────────

async fn run_poll_watcher(
    uri: String,
    interval_ms: u64,
    cancel: CancellationToken,
    ctx: WatchContext,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
) {
    // Content-hash comparison against the SHA-256 of the last fetch. The
    // last holder of the URI's shard left it in the store, wherever it ran,
    // so a change made while the shard moved is still told.
    let mut last_hash: Option<[u8; 32]> = None;
    let mut baseline_read = false;
    let mut written: Option<Instant> = None;
    let interval = poll_interval(interval_ms);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!(uri = %uri, "poll watcher cancelled");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }

        // A replica that gave the shard up leaves the fetch, the baseline and
        // the fan-out to the new holder: a baseline written here would hide
        // the change from it. Should the shard come back, the baseline the
        // other holder left is read again.
        if !ctx.shards.owns_uri(&uri) {
            baseline_read = false;
            continue;
        }
        if !baseline_read {
            last_hash = match &ctx.state {
                Some(state) => state.baseline(&uri).await.unwrap_or_else(|error| {
                    debug!(uri = %uri, %error, "poll: stored baseline unreadable; this fetch sets one");
                    None
                }),
                None => last_hash,
            };
            baseline_read = true;
            written = None;
        }

        let body = match (ctx.resource_fetcher)(&uri) {
            Some(b) => b,
            None => {
                // A failed read leaves the baseline untouched, so a broken
                // upstream is silence rather than a fire. The counter is the
                // only way to tell that apart from a resource that is simply
                // not changing.
                metrics::counter!("mcpg_watch_poll_failures_total").increment(1);
                debug!(uri = %uri, "poll: resource fetch returned None, skipping");
                continue;
            }
        };

        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        // The fetch can outlast the lease.
        if !ctx.shards.owns_uri(&uri) {
            baseline_read = false;
            continue;
        }
        let changed = last_hash.is_some_and(|prev| prev != hash);
        let stale = written.is_none_or(|at| at.elapsed() >= BASELINE_REFRESH);
        last_hash = Some(hash);
        if (changed || stale)
            && let Some(state) = &ctx.state
        {
            match state.set_baseline(&uri, hash).await {
                Ok(()) => written = Some(Instant::now()),
                Err(error) => debug!(uri = %uri, %error, "poll: baseline not stored; next fetch"),
            }
        }

        if changed {
            let count = notify_subscribers_filtered(
                &uri,
                &*ctx.subscription_store,
                &*ctx.delivery_publish,
                notification_filter.as_ref(),
                compiled_filter_program.as_deref(),
                &EventContext::default(),
            );
            metrics::counter!("mcpg_watch_fired_total", "strategy" => "poll").increment(1);
            metrics::counter!("mcpg_watch_notifications_sent_total", "strategy" => "poll")
                .increment(count as u64);
            if count > 0 {
                info!(
                    uri = %uri,
                    subscriber_count = count,
                    "poll: resource change detected, notifications sent"
                );
            }
            // Emit an audit event: the poll watch strategy fired.
            if let Some(registry) = ctx.plugin_registry.clone() {
                let uri_owned = uri.clone();
                let count_u64 = count as u64;
                tokio::spawn(async move {
                    let event = mcpg_plugin_host::audit_events::watch_fired_event(
                        &uri_owned, "poll", None, count_u64,
                    );
                    let _ = registry.emit_audit_event(&event).await;
                });
            }
        }
    }
}

// NATS and Kafka topic watchers live in their respective plugin crates
// (mcpg-plugin-backend-nats, mcpg-plugin-backend-kafka) under the shared
// `WatchStrategyPlugin` trait. The in-engine code above routes
// `WatchStrategy::Plugin { kind, spec }` to those plugins via the
// plugin registry.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::subscription_store::KvBackedSubscriptionStore;
    use std::sync::Mutex;

    #[tokio::test]
    async fn watch_engine_starts_and_shuts_down() {
        let engine = WatchEngine::start(
            HashMap::new(),
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100)),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn poll_watcher_hash_change_detection() {
        let hash1 = {
            let mut h = Sha256::new();
            h.update(b"version1");
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let hash2 = {
            let mut h = Sha256::new();
            h.update(b"version2");
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_ne!(hash1, hash2);
        // Same content → same hash
        let hash1b = {
            let mut h = Sha256::new();
            h.update(b"version1");
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_eq!(hash1, hash1b);
    }

    /// The control loop ends either on `Shutdown` or when its last sender
    /// drops — a retired runtime. Both must cancel the watchers: a
    /// `CancellationToken` does not fire when dropped, so a loop that exits
    /// without cancelling leaves every watcher task parked forever, and each
    /// config reload adds another generation of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watchers_are_cancelled_when_the_loop_loses_its_last_sender() {
        let uri = "mem://parked";
        let mut configs = HashMap::new();
        configs.insert(
            uri.to_owned(),
            WatchConfig {
                uri: uri.to_owned(),
                // A webhook watcher only ever ends by cancellation, so the
                // store handle it holds is a precise liveness probe.
                strategy: WatchStrategy::Webhook {
                    token: "t".to_owned(),
                    previous_tokens: Vec::new(),
                },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );
        let store: Arc<dyn SubscriptionStore> =
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        let engine = WatchEngine::start(
            configs,
            Arc::clone(&store),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );
        engine.notify_subscribe(uri).await;
        assert_eq!(engine.active_watch_count().await, 1);
        assert!(
            Arc::strong_count(&store) > 1,
            "the running watcher holds a store handle"
        );

        drop(engine);
        for _ in 0..400 {
            if Arc::strong_count(&store) == 1 {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            Arc::strong_count(&store),
            1,
            "the watcher task must end when the engine loop does"
        );
    }

    #[tokio::test]
    async fn noop_engine_is_safe() {
        let engine = WatchEngine::noop();
        engine.notify_subscribe("test://data").await;
        engine.notify_unsubscribe("test://data").await;
        engine.notify_resource_changed("test://nothing").await;
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn external_notify_delivers_to_subscribers() {
        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store.subscribe("sess-1", "test://data", None).unwrap();
        sub_store.subscribe("sess-2", "test://data", None).unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();

        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let engine = WatchEngine::start(HashMap::new(), sub_store, publish, Arc::new(|_| None));

        engine.notify_resource_changed("test://data").await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        {
            let msgs = delivered.lock().unwrap();
            assert_eq!(msgs.len(), 2);
            assert!(msgs.iter().any(|(sid, _)| sid == "sess-1"));
            assert!(msgs.iter().any(|(sid, _)| sid == "sess-2"));
            for (_, msg) in msgs.iter() {
                assert_eq!(msg.kind, DeliveryKind::ResourceUpdated);
            }
        }

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn webhook_token_resolution() {
        let mut configs = HashMap::new();
        configs.insert(
            "file:///config.yaml".to_owned(),
            WatchConfig {
                uri: "file:///config.yaml".to_owned(),
                strategy: WatchStrategy::Webhook {
                    token: "abc123".to_owned(),
                    previous_tokens: vec!["superseded".to_owned()],
                },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );
        configs.insert(
            "file:///other.yaml".to_owned(),
            WatchConfig {
                uri: "file:///other.yaml".to_owned(),
                strategy: WatchStrategy::Poll { interval_ms: 60 },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );

        let engine = WatchEngine::start(
            configs,
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100)),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );

        // The rotation window: a superseded token routes to the same resource
        // as the live one, so senders re-registering after the deploy keep
        // working instead of 404ing until someone notices.
        assert_eq!(
            engine.resolve_webhook_token("superseded"),
            Some(&"file:///config.yaml".to_owned()),
            "a previous token must still resolve during rotation"
        );

        assert_eq!(
            engine.resolve_webhook_token("abc123"),
            Some(&"file:///config.yaml".to_owned())
        );
        assert_eq!(engine.resolve_webhook_token("nonexistent"), None);
        // One webhook resource, two live routes into it: the current token and
        // the one it superseded. The poll resource contributes none.
        assert_eq!(engine.webhook_tokens().len(), 2);

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn list_watches_reports_running_watchers_only() {
        let mut configs = HashMap::new();
        for (uri, interval) in [("res://a", 60_000u64), ("res://b", 60_000)] {
            configs.insert(
                uri.to_owned(),
                WatchConfig {
                    uri: uri.to_owned(),
                    strategy: WatchStrategy::Poll {
                        interval_ms: interval,
                    },
                    notification_filter: None,
                    compiled_filter_program: None,
                },
            );
        }
        let engine = WatchEngine::start(
            configs,
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100)),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );

        // Configured but unsubscribed: no watcher runs, so nothing is listed.
        assert!(engine.list_watches().await.is_empty());

        engine.notify_subscribe("res://b").await;
        engine.notify_subscribe("res://a").await;
        engine.notify_subscribe("res://a").await;

        let listed = engine.list_watches().await;
        assert_eq!(listed.len(), 2);
        // Sorted by URI regardless of subscribe order.
        assert_eq!(listed[0].uri, "res://a");
        assert_eq!(listed[0].strategy, "poll");
        assert_eq!(listed[0].subscriber_count, 2);
        assert_eq!(listed[1].uri, "res://b");
        assert_eq!(listed[1].subscriber_count, 1);

        engine.notify_unsubscribe("res://b").await;
        let listed = engine.list_watches().await;
        assert_eq!(
            listed.len(),
            1,
            "a watcher with no subscribers is torn down"
        );
        assert_eq!(listed[0].uri, "res://a");

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn external_notify_no_subscribers_is_safe() {
        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();

        let engine = WatchEngine::start(
            HashMap::new(),
            sub_store,
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            }),
            Arc::new(|_| None),
        );

        engine.notify_resource_changed("test://nothing").await;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(delivered.lock().unwrap().is_empty());
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn build_resource_updated_message_format() {
        let msg = build_resource_updated_message("file:///test.txt");
        assert_eq!(msg["jsonrpc"], "2.0");
        assert_eq!(msg["method"], "notifications/resources/updated");
        assert_eq!(msg["params"]["uri"], "file:///test.txt");
    }

    #[tokio::test]
    async fn strategy_name_labels() {
        assert_eq!(
            strategy_name(&WatchStrategy::Poll { interval_ms: 30 }),
            "poll"
        );
        assert_eq!(
            strategy_name(&WatchStrategy::Webhook {
                token: "x".to_owned(),
                previous_tokens: Vec::new(),
            }),
            "webhook"
        );
    }

    // ── Subject-Scoped Notification Filter Tests (F1) ───────────────────

    #[tokio::test]
    async fn subject_id_filter_delivers_only_to_matching_principal() {
        use crate::runtime::subscription_store::SubscriberIdentity;

        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store
            .subscribe(
                "sess-1",
                "test://data",
                Some(SubscriberIdentity {
                    session_id: "sess-1".to_owned(),
                    principal_id: Some("user-42".to_owned()),
                    ..Default::default()
                }),
            )
            .unwrap();
        sub_store
            .subscribe(
                "sess-2",
                "test://data",
                Some(SubscriberIdentity {
                    session_id: "sess-2".to_owned(),
                    principal_id: Some("user-99".to_owned()),
                    ..Default::default()
                }),
            )
            .unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let count = notify_subscribers_filtered(
            "test://data",
            &*sub_store,
            &*publish,
            Some(&NotificationFilterConfig::SubjectId),
            None,
            &EventContext {
                user_id: Some("user-42".to_owned()),
                session_id: None,
            },
        );

        assert_eq!(count, 1);
        let msgs = delivered.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, "sess-1");
    }

    #[tokio::test]
    async fn subject_id_filter_falls_back_to_all_when_no_event_user() {
        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store.subscribe("sess-1", "test://data", None).unwrap();
        sub_store.subscribe("sess-2", "test://data", None).unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let count = notify_subscribers_filtered(
            "test://data",
            &*sub_store,
            &*publish,
            Some(&NotificationFilterConfig::SubjectId),
            None,
            &EventContext::default(), // no user_id
        );

        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn session_id_filter_delivers_only_to_originating_session() {
        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store.subscribe("sess-1", "test://data", None).unwrap();
        sub_store.subscribe("sess-2", "test://data", None).unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let count = notify_subscribers_filtered(
            "test://data",
            &*sub_store,
            &*publish,
            Some(&NotificationFilterConfig::SessionId),
            None,
            &EventContext {
                user_id: None,
                session_id: Some("sess-2".to_owned()),
            },
        );

        assert_eq!(count, 1);
        let msgs = delivered.lock().unwrap();
        assert_eq!(msgs[0].0, "sess-2");
    }

    #[tokio::test]
    async fn all_filter_delivers_to_everyone() {
        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store.subscribe("sess-1", "test://data", None).unwrap();
        sub_store.subscribe("sess-2", "test://data", None).unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let count = notify_subscribers_filtered(
            "test://data",
            &*sub_store,
            &*publish,
            Some(&NotificationFilterConfig::All),
            None,
            &EventContext::default(),
        );

        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn expression_filter_evaluates_cel() {
        use crate::runtime::subscription_store::SubscriberIdentity;

        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store
            .subscribe(
                "sess-1",
                "test://data",
                Some(SubscriberIdentity {
                    session_id: "sess-1".to_owned(),
                    principal_id: Some("user-42".to_owned()),
                    trust_level: "verified".to_owned(),
                    roles: vec!["admin".to_owned()],
                    ..Default::default()
                }),
            )
            .unwrap();
        sub_store
            .subscribe(
                "sess-2",
                "test://data",
                Some(SubscriberIdentity {
                    session_id: "sess-2".to_owned(),
                    principal_id: Some("user-99".to_owned()),
                    trust_level: "header_asserted".to_owned(),
                    roles: vec!["viewer".to_owned()],
                    ..Default::default()
                }),
            )
            .unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        let program = compile_notification_filter("subscriber.trust_level == \"verified\"")
            .expect("CEL program should compile");

        let count = notify_subscribers_filtered(
            "test://data",
            &*sub_store,
            &*publish,
            Some(&NotificationFilterConfig::Expression {
                expression: "subscriber.trust_level == \"verified\"".to_owned(),
            }),
            Some(&program),
            &EventContext::default(),
        );

        assert_eq!(count, 1);
        let msgs = delivered.lock().unwrap();
        assert_eq!(msgs[0].0, "sess-1");
    }

    // ---- plugin-strategy watcher fan-out ---------------------------------

    /// Test plugin that emits N events from a background task, then
    /// idles until the handle is cancelled. Mirrors what a real
    /// transport plugin (nats_topic, postgres_listen_notify, …) would
    /// do — the sink handles subscription lookup + filter + delivery.
    struct TestEmittingPlugin {
        manifest: mcpg_plugin_protocol::PluginManifest,
        event_count: usize,
        acknowledged: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[async_trait]
    impl mcpg_plugin_protocol::WatchStrategyPlugin for TestEmittingPlugin {
        fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
            &self.manifest
        }
        fn kind(&self) -> &str {
            "test_emit"
        }
        async fn watch(
            &self,
            _uri: &str,
            _spec: &serde_json::Value,
            sink: Arc<dyn WatchEventSink>,
        ) -> Result<Box<dyn mcpg_plugin_protocol::WatchHandle>, mcpg_plugin_protocol::WatchError>
        {
            for n in 0..self.event_count {
                sink.emit(WatchEvent {
                    upstream_cursor: Some(serde_json::json!({ "n": n })),
                    ..WatchEvent::default()
                })
                .await;
            }
            Ok(Box::new(RecordingHandle(Arc::clone(&self.acknowledged))))
        }
    }

    struct RecordingHandle(Arc<Mutex<Vec<serde_json::Value>>>);
    #[async_trait]
    impl mcpg_plugin_protocol::WatchHandle for RecordingHandle {
        async fn cancel(&self) {}
        async fn acknowledge(&self, position: &serde_json::Value) {
            self.0.lock().unwrap().push(position.clone());
        }
    }

    #[tokio::test]
    async fn plugin_strategy_delivers_events_to_subscribers() {
        use mcpg_plugin_protocol::{PluginClass, PluginManifest};

        let sub_store = Arc::new(KvBackedSubscriptionStore::new_in_memory(100));
        sub_store
            .subscribe("sess-1", "mem://pluginwatch", None)
            .unwrap();
        sub_store
            .subscribe("sess-2", "mem://pluginwatch", None)
            .unwrap();

        let delivered = Arc::new(Mutex::new(Vec::<(String, DeliveryMessage)>::new()));
        let delivered_clone = delivered.clone();
        let publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync> =
            Arc::new(move |sid, msg| {
                delivered_clone.lock().unwrap().push((sid.to_owned(), msg));
            });

        // Registry with one strategy plugin that will emit two events.
        let mut registry = mcpg_plugin_host::PluginRegistry::new();
        let acknowledged = Arc::new(Mutex::new(Vec::new()));
        let plugin = Arc::new(TestEmittingPlugin {
            acknowledged: Arc::clone(&acknowledged),
            manifest: PluginManifest {
                id: "test.emit".into(),
                version: "0.1.0".into(),
                name: "test".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".to_owned(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            event_count: 2,
        });
        registry
            .register_watch_strategy(plugin, mcpg_plugin_protocol::PluginTier::Native)
            .expect("register strategy");
        let registry = Arc::new(registry);

        let mut configs = HashMap::new();
        configs.insert(
            "mem://pluginwatch".to_owned(),
            WatchConfig {
                uri: "mem://pluginwatch".to_owned(),
                strategy: WatchStrategy::Plugin {
                    kind: "test_emit".into(),
                    spec: serde_json::json!({}),
                },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );

        let engine = WatchEngine::start_with_plugins(
            configs,
            sub_store,
            publish,
            Arc::new(|_| None),
            Some(registry),
            None,
        );

        engine.notify_subscribe("mem://pluginwatch").await;
        // Plugin emits synchronously inside watch(); wait long enough
        // for the loop to spawn the watcher and drain both events.
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        {
            let msgs = delivered.lock().unwrap();
            // 2 events × 2 subscribers.
            assert_eq!(msgs.len(), 4, "expected 4 deliveries, got {}", msgs.len());
            for (_, msg) in msgs.iter() {
                assert_eq!(msg.kind, DeliveryKind::ResourceUpdated);
                assert_eq!(
                    msg.jsonrpc_message["method"],
                    "notifications/resources/updated"
                );
                assert_eq!(msg.jsonrpc_message["params"]["uri"], "mem://pluginwatch");
            }
        }
        assert_eq!(
            *acknowledged.lock().unwrap(),
            [serde_json::json!({ "n": 0 }), serde_json::json!({ "n": 1 })],
            "a notified change is acknowledged, in order"
        );

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn plugin_strategy_without_registry_idles_gracefully() {
        let mut configs = HashMap::new();
        configs.insert(
            "mem://noreg".to_owned(),
            WatchConfig {
                uri: "mem://noreg".to_owned(),
                strategy: WatchStrategy::Plugin {
                    kind: "ghost".into(),
                    spec: serde_json::json!({}),
                },
                notification_filter: None,
                compiled_filter_program: None,
            },
        );
        let engine = WatchEngine::start(
            configs,
            Arc::new(KvBackedSubscriptionStore::new_in_memory(100)),
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
        );
        engine.notify_subscribe("mem://noreg").await;
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        engine.shutdown().await;
    }
}
