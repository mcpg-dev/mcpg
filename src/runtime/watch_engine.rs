//! Resource watch engine — detects resource changes via poll, NATS,
//! Kafka, or webhook and fans out `notifications/resources/updated`
//! to subscribed sessions through the delivery bus.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::NotificationFilterConfig;
use crate::protocol::{JSONRPC_VERSION, ResourceUpdatedNotification, ResourceUpdatedParams};
use crate::runtime::pipeline_store::{DeliveryKind, DeliveryMessage};
use crate::runtime::subscription_store::{SubscriberIdentity, SubscriptionStore};
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_protocol::async_trait;
use mcpg_plugin_protocol::{WatchEvent, WatchEventSink};

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
    Webhook { token: String },
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
    subscriber_count: usize,
}

/// Resolves a subscribed URI with no static `watch:` config to a
/// synthesized [`WatchConfig`] — the federated-resource hook: a
/// federated URI whose upstream cannot push `resources/updated` gets a
/// poll watcher manufactured on first subscribe. `None` keeps today's
/// ignore behavior.
pub type WatchProbe = Arc<dyn Fn(&str) -> Option<WatchConfig> + Send + Sync>;

/// Channel message to communicate with the watch engine control loop.
#[derive(Debug)]
pub enum WatchCommand {
    /// A session subscribed to a resource URI.
    Subscribe { uri: String },
    /// A session unsubscribed from a resource URI.
    Unsubscribe { uri: String },
    /// External notification that a resource changed (webhook / admin API).
    ExternalNotify { uri: String },
    /// Report how many watchers are running.
    CountWatchers {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    /// Shut down all watchers.
    Shutdown,
}

/// The watch engine manages background watchers for subscribed resources.
///
/// It activates a watcher when the first client subscribes to a resource and
/// deactivates it when the last subscriber leaves. Change detection depends on
/// the `WatchStrategy` configured for each resource binding.
///
/// For multi-instance deployments, the delivery happens through the shared
/// `DeliveryBus` (NATS / Redis pub/sub), so notifications reach all instances.
#[derive(Debug, Clone)]
pub struct WatchEngine {
    command_tx: mpsc::Sender<WatchCommand>,
    /// Reverse map: webhook token → resource URI (for inbound webhook routing).
    webhook_tokens: Arc<HashMap<String, String>>,
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

        // Build the webhook token → URI reverse map.
        let mut tokens = HashMap::new();
        for (uri, config) in &watch_configs {
            if let WatchStrategy::Webhook { token } = &config.strategy {
                tokens.insert(token.clone(), uri.clone());
            }
        }

        // The control loop needs a reactor. Runtime construction in
        // synchronous test contexts has none — degrade to an inert
        // engine there (the dropped receiver makes every notify a
        // no-op), keeping the webhook map for sync resolution.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(watch_engine_loop(
                    command_rx,
                    watch_configs,
                    subscription_store,
                    delivery_publish,
                    resource_fetcher,
                    plugin_registry,
                    watch_probe,
                ));
            }
            Err(_) => drop(command_rx),
        }

        Self {
            command_tx,
            webhook_tokens: Arc::new(tokens),
        }
    }

    /// Create a no-op engine (when no resource watches are configured).
    pub fn noop() -> Self {
        let (command_tx, _) = mpsc::channel(1);
        Self {
            command_tx,
            webhook_tokens: Arc::new(HashMap::new()),
        }
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

    /// Shut down the engine and all active watchers.
    pub async fn shutdown(&self) {
        let _ = self.command_tx.send(WatchCommand::Shutdown).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn watch_engine_loop(
    mut command_rx: mpsc::Receiver<WatchCommand>,
    watch_configs: HashMap<String, WatchConfig>,
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
    plugin_registry: Option<Arc<PluginRegistry>>,
    watch_probe: Option<WatchProbe>,
) {
    let mut active_watches: HashMap<String, WatchHandle> = HashMap::new();

    while let Some(cmd) = command_rx.recv().await {
        match cmd {
            WatchCommand::Subscribe { uri } => {
                if let Some(handle) = active_watches.get_mut(&uri) {
                    handle.subscriber_count += 1;
                    debug!(uri = %uri, subscribers = handle.subscriber_count, "watch: subscriber added");
                } else if let Some(config) = watch_configs
                    .get(&uri)
                    .cloned()
                    .or_else(|| watch_probe.as_ref().and_then(|probe| probe(&uri)))
                {
                    let cancel = CancellationToken::new();
                    let handle = WatchHandle {
                        cancel: cancel.clone(),
                        subscriber_count: 1,
                    };

                    let sub_store = subscription_store.clone();
                    let publish = delivery_publish.clone();
                    let fetcher = resource_fetcher.clone();
                    let uri_owned = uri.clone();
                    let strategy = config.strategy.clone();
                    let nf = config.notification_filter.clone();
                    let compiled = config.compiled_filter_program.clone();
                    let registry = plugin_registry.clone();

                    tokio::spawn(async move {
                        run_watcher(
                            uri_owned, strategy, cancel, sub_store, publish, fetcher, nf, compiled,
                            registry,
                        )
                        .await;
                    });

                    active_watches.insert(uri.clone(), handle);
                    info!(uri = %uri, strategy = strategy_name(&config.strategy), "watch: watcher started");
                } else {
                    debug!(uri = %uri, "watch: no config for resource, ignoring subscribe");
                }
            }
            WatchCommand::Unsubscribe { uri } => {
                if let Some(handle) = active_watches.get_mut(&uri) {
                    handle.subscriber_count = handle.subscriber_count.saturating_sub(1);
                    if handle.subscriber_count == 0 {
                        handle.cancel.cancel();
                        active_watches.remove(&uri);
                        info!(uri = %uri, "watch: watcher stopped (no subscribers)");
                    } else {
                        debug!(uri = %uri, subscribers = handle.subscriber_count, "watch: subscriber removed");
                    }
                }
            }
            WatchCommand::ExternalNotify { uri } => {
                // Directly fan out notifications to subscribers, respecting the filter.
                let (filter, compiled) = watch_configs
                    .get(&uri)
                    .and_then(|c| {
                        c.notification_filter
                            .as_ref()
                            .map(|f| (Some(f), c.compiled_filter_program.as_deref()))
                    })
                    .unwrap_or((None, None));
                let count = notify_subscribers_filtered(
                    &uri,
                    &*subscription_store,
                    &*delivery_publish,
                    filter,
                    compiled,
                    &EventContext::default(),
                );
                if count > 0 {
                    info!(uri = %uri, subscriber_count = count, "watch: external notify delivered");
                } else {
                    debug!(uri = %uri, "watch: external notify but no subscribers");
                }
                // Emit an audit event: the webhook watch strategy fired.
                if let Some(registry) = plugin_registry.clone() {
                    let uri_owned = uri.clone();
                    let count_u64 = count as u64;
                    tokio::spawn(async move {
                        let event = mcpg_plugin_host::audit_events::watch_fired_event(
                            &uri_owned, "webhook", None, count_u64,
                        );
                        let _ = registry.emit_audit_event(&event).await;
                    });
                }
            }
            WatchCommand::CountWatchers { reply } => {
                let _ = reply.send(active_watches.len());
            }
            WatchCommand::Shutdown => break,
        }
    }

    // Cancel on EVERY exit, not just the `Shutdown` command: the loop also
    // ends when its last sender drops (a retired runtime), and a
    // `CancellationToken` does not cancel when dropped — so exiting without
    // this would leave every spawned watcher polling its resource until the
    // process ends.
    for (uri, handle) in active_watches.drain() {
        handle.cancel.cancel();
        debug!(uri = %uri, "watch: watcher cancelled");
    }
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
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
    plugin_registry: Option<Arc<PluginRegistry>>,
) {
    match strategy {
        WatchStrategy::Poll { interval_ms } => {
            run_poll_watcher(
                uri,
                interval_ms,
                cancel,
                subscription_store,
                delivery_publish,
                resource_fetcher,
                notification_filter,
                compiled_filter_program,
                plugin_registry,
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
                subscription_store,
                delivery_publish,
                notification_filter,
                compiled_filter_program,
                plugin_registry,
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
}

#[async_trait]
impl WatchEventSink for ResourceUpdatedSink {
    async fn emit(&self, event: WatchEvent) {
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
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
    plugin_registry: Option<Arc<PluginRegistry>>,
) {
    let Some(registry) = plugin_registry else {
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

    let sink = Arc::new(ResourceUpdatedSink {
        uri: uri.clone(),
        subscription_store,
        delivery_publish,
        notification_filter,
        compiled_filter_program,
        plugin_kind: kind.clone(),
        plugin_registry: Some(registry.clone()),
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
    cancel.cancelled().await;
    handle.cancel().await;
    debug!(uri = %uri, kind = %kind, "plugin watch: watcher cancelled");
}

// ─── Poll Watcher ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_poll_watcher(
    uri: String,
    interval_ms: u64,
    cancel: CancellationToken,
    subscription_store: Arc<dyn SubscriptionStore>,
    delivery_publish: Arc<dyn Fn(&str, DeliveryMessage) + Send + Sync>,
    resource_fetcher: Arc<dyn Fn(&str) -> Option<String> + Send + Sync>,
    notification_filter: Option<NotificationFilterConfig>,
    compiled_filter_program: Option<Arc<cel::Program>>,
    plugin_registry: Option<Arc<PluginRegistry>>,
) {
    // Content-hash comparison: store the SHA-256 of the last fetch to detect changes.
    let last_hash: Mutex<Option<[u8; 32]>> = Mutex::new(None);
    let interval = poll_interval(interval_ms);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!(uri = %uri, "poll watcher cancelled");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }

        let body = match resource_fetcher(&uri) {
            Some(b) => b,
            None => {
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

        let changed = {
            let mut last = last_hash.lock().unwrap();
            if let Some(prev) = *last {
                if prev == hash {
                    false
                } else {
                    *last = Some(hash);
                    true
                }
            } else {
                *last = Some(hash);
                false
            }
        };

        if changed {
            let count = notify_subscribers_filtered(
                &uri,
                &*subscription_store,
                &*delivery_publish,
                notification_filter.as_ref(),
                compiled_filter_program.as_deref(),
                &EventContext::default(),
            );
            if count > 0 {
                info!(
                    uri = %uri,
                    subscriber_count = count,
                    "poll: resource change detected, notifications sent"
                );
            }
            // Emit an audit event: the poll watch strategy fired.
            if let Some(registry) = plugin_registry.clone() {
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

        assert_eq!(
            engine.resolve_webhook_token("abc123"),
            Some(&"file:///config.yaml".to_owned())
        );
        assert_eq!(engine.resolve_webhook_token("nonexistent"), None);
        assert_eq!(engine.webhook_tokens().len(), 1);

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
                token: "x".to_owned()
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
            for _ in 0..self.event_count {
                sink.emit(WatchEvent::default()).await;
            }
            Ok(Box::new(NoopHandle))
        }
    }

    struct NoopHandle;
    #[async_trait]
    impl mcpg_plugin_protocol::WatchHandle for NoopHandle {
        async fn cancel(&self) {}
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
        let plugin = Arc::new(TestEmittingPlugin {
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
