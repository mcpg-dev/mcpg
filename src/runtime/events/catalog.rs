//! The event catalog: every declared event type, compiled.
//!
//! Built from `mcp.capabilities.events` at boot and on every reload: schemas
//! compiled through the schema-safety checks, `match` compiled to a CEL
//! program, inbound secrets resolved, and each type's source key derived. A
//! type that fails any step fails the whole build, so a broken declaration
//! never serves half-checked.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use mcpg_mcp_wire::shared::canonical::canonical_value_bytes;
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::{DeliveryMode, EventDescriptor};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use super::inbound::{InboundFilter, InboundVerifier, RateLimiter};
use super::keys::{EventsKeys, SourceScope};
use super::occurrence::StoredOccurrence;
use crate::config::AppConfig;
pub use crate::config::events::BuiltinEventSource;
use crate::config::events::{
    EventDeliveryMode, EventReplay, EventRetentionConfig, EventSource, EventTransformConfig,
    EventTypeConfig,
};
pub use crate::config::events::{default_input_schema, default_payload_schema};
use crate::runtime::RequestIdentity;
use crate::runtime::watch_engine::WatchStrategy;

/// Synthetic URI a `watch` source's plugin watcher is started on.
pub fn watch_source_uri(name: &str) -> String {
    format!("{}{name}", mcpg_plugin_protocol::EVENT_SOURCE_URI_PREFIX)
}

/// How a `resource` source observes its resource.
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceStrategy {
    /// Read the resource every `interval_ms` and compare a hash.
    Poll { interval_ms: u64 },
    /// A plugin watch strategy on the resource's URI.
    Plugin { kind: String, spec: Value },
}

/// An `inbound` source, ready to serve its route.
#[derive(Debug)]
pub struct InboundSpec {
    pub source_id: String,
    pub verifier: InboundVerifier,
    pub filter: InboundFilter,
    pub event_id_pointer: Option<String>,
    pub timestamp_pointer: Option<String>,
    pub rate: RateLimiter,
}

/// What a payload-bearing watch source takes from its plugin.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchPayload {
    /// The plugin's `WatchEvent.event_type` this type takes.
    pub event_type: String,
    /// The plugin resumes from the last `upstream_cursor`.
    pub resume: bool,
}

/// Where a type's occurrences come from.
#[derive(Debug)]
pub enum SourceSpec {
    /// A plugin watch strategy on the type's synthetic URI, run where its
    /// plugin places it; with `payload`, one of the event types the
    /// strategy declares.
    Watch {
        kind: String,
        spec: Value,
        placement: mcpg_plugin_protocol::EventPlacement,
        payload: Option<WatchPayload>,
    },
    /// The watch of a resource binding.
    Resource {
        uri: String,
        strategy: ResourceStrategy,
    },
    /// Signed webhooks on `/webhooks/events/{source_id}`.
    Inbound(InboundSpec),
    /// An event the gateway raises itself.
    Builtin(BuiltinEventSource),
    /// Upstream subscriptions to an event type a federation imported, one
    /// per set of arguments in demand (and, with `per_principal` sharing,
    /// per subscriber), read in `mode`.
    Federation {
        federation: String,
        upstream_name: String,
        mode: UpstreamMode,
        sharing: crate::config::federation::UpstreamEventSharing,
    },
}

/// How a federated type's upstream subscriptions read the upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamMode {
    /// An upstream webhook subscription delivering to this gateway.
    Webhook,
    Push,
    Poll,
}

/// An event type a federation imported: the upstream's descriptor, under
/// the name this gateway serves it as.
#[derive(Debug, Clone, PartialEq)]
pub struct FederatedEventType {
    pub federation: String,
    /// The served name: the federation's `event_prefix` and the upstream
    /// name.
    pub name: String,
    pub upstream_name: String,
    pub descriptor: EventDescriptor,
    pub delivery: crate::config::federation::UpstreamEventDelivery,
    pub sharing: crate::config::federation::UpstreamEventSharing,
    pub retention: crate::config::events::EventRetentionConfig,
}

/// What the federations of a runtime imported of MCP Events.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImportedEvents {
    pub types: Vec<FederatedEventType>,
    /// A federation that imports event types has no import yet, so a type
    /// missing from `types` may still come.
    pub pending: bool,
}

/// [`ImportedEvents`] as a runtime publishes them.
pub type FederatedEvents = Arc<ImportedEvents>;

impl SourceSpec {
    /// A bounded label for metrics and derived ids.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Watch { .. } => "watch",
            Self::Resource { .. } => "resource",
            Self::Inbound(_) => "inbound",
            Self::Builtin(_) => "builtin",
            Self::Federation { .. } => "federation",
        }
    }

    /// Whether a task has to run on the events owner to produce
    /// occurrences. An inbound source is fed by its route, a builtin one by
    /// the gateway, and a watch placed on every replica runs there.
    pub fn needs_runner(&self) -> bool {
        match self {
            Self::Inbound(_) | Self::Builtin(_) => false,
            Self::Watch { .. } => !self.runs_on_every_replica(),
            Self::Resource { .. } | Self::Federation { .. } => true,
        }
    }

    /// Whether the source runs on every replica and hands its occurrences
    /// to the owner through the inbox.
    pub fn runs_on_every_replica(&self) -> bool {
        matches!(
            self,
            Self::Watch {
                placement: mcpg_plugin_protocol::EventPlacement::EveryReplica,
                ..
            }
        )
    }

    /// Whether the source keeps positions to resume from, so a restart
    /// loses nothing it can recover. A federated source keeps one per
    /// upstream subscription and marks its own gaps.
    pub fn resumes(&self) -> bool {
        matches!(
            self,
            Self::Watch {
                payload: Some(WatchPayload { resume: true, .. }),
                ..
            } | Self::Federation { .. }
        )
    }
}

/// One compiled event type.
pub struct EventType {
    pub name: String,
    pub description: Option<String>,
    /// Delivery modes offered: the declared ones the config enables.
    pub delivery: Vec<DeliveryMode>,
    pub input_schema: Value,
    pub payload_schema: Value,
    input_validator: jsonschema::Validator,
    payload_validator: jsonschema::Validator,
    pub match_expr: Option<String>,
    match_program: Option<cel::Program>,
    pub transform: Option<EventTransformConfig>,
    pub retention: EventRetentionConfig,
    pub replay: EventReplay,
    pub always_on: bool,
    pub source: SourceSpec,
    /// Key of this type's log and the scope of its cursors.
    pub source_key: String,
    /// Changes whenever the `events/list` descriptor changes.
    pub descriptor_fingerprint: String,
    /// Changes whenever the source must be restarted.
    pub source_fingerprint: String,
    /// Moves only on a schema change that is not additive.
    pub schema_epoch: u32,
}

impl fmt::Debug for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventType")
            .field("name", &self.name)
            .field("delivery", &self.delivery)
            .field("source", &self.source.kind())
            .field("source_key", &self.source_key)
            .finish_non_exhaustive()
    }
}

impl EventType {
    /// Whether the gateway raises this type itself (`source: builtin`).
    pub fn is_builtin(&self) -> bool {
        matches!(self.source, SourceSpec::Builtin(_))
    }

    /// Of `delivered` deliveries of this type, those the usage report counts
    /// toward the plan's delivery allowance and its overage: only
    /// operator-defined types are billed, never the gateway's own.
    pub fn billable_deliveries(&self, delivered: u64) -> u64 {
        if self.is_builtin() { 0 } else { delivered }
    }

    /// The `events/list` descriptor.
    pub fn descriptor(&self) -> EventDescriptor {
        EventDescriptor {
            name: self.name.clone(),
            description: self.description.clone(),
            delivery: self.delivery.clone(),
            input_schema: self.input_schema.clone(),
            payload_schema: self.payload_schema.clone(),
            meta: None,
        }
    }

    /// Whether subscription `arguments` match the input schema.
    pub fn arguments_are_valid(&self, arguments: &Map<String, Value>) -> bool {
        self.input_validator
            .is_valid(&Value::Object(arguments.clone()))
    }

    /// Whether occurrence `data` matches the payload schema.
    pub fn payload_is_valid(&self, data: &Value) -> bool {
        self.payload_validator.is_valid(data)
    }

    /// Whether the type offers `mode`.
    pub fn offers(&self, mode: DeliveryMode) -> bool {
        self.delivery.contains(&mode)
    }

    /// Whether a subscription with `arguments`, held by `subscriber`,
    /// receives `occurrence`. A type with no `match` delivers everything;
    /// an expression that fails or does not yield a boolean delivers
    /// nothing.
    pub fn matches(
        &self,
        arguments: &Map<String, Value>,
        occurrence: &StoredOccurrence,
        subscriber: &RequestIdentity,
    ) -> bool {
        let Some(program) = &self.match_program else {
            return true;
        };
        let mut ctx = cel::Context::default();
        let event = json!({
            "eventId": occurrence.event_id,
            "name": self.name,
            "timestamp": occurrence.timestamp,
            "data": occurrence.data,
        });
        ctx.add_variable_from_value(
            "arguments",
            mcpg_expr::json_to_cel(&Value::Object(arguments.clone())),
        );
        ctx.add_variable_from_value("event", mcpg_expr::json_to_cel(&event));
        ctx.add_variable_from_value(
            "subscriber",
            mcpg_expr::json_to_cel(&subscriber_value(subscriber)),
        );
        match program.execute(&ctx) {
            Ok(cel::Value::Bool(matched)) => matched,
            Ok(_) | Err(_) => {
                metrics::counter!("mcpg_events_match_errors_total", "event" => self.name.clone())
                    .increment(1);
                false
            }
        }
    }
}

fn subscriber_value(identity: &RequestIdentity) -> Value {
    let trust = match identity.trust_level() {
        crate::runtime::RequestTrustLevel::Unauthenticated => "unauthenticated",
        crate::runtime::RequestTrustLevel::HeaderAsserted => "header_asserted",
        crate::runtime::RequestTrustLevel::Verified => "verified",
    };
    let attributes = match identity {
        RequestIdentity::Verified { attributes, .. } => json!(attributes),
        _ => json!({}),
    };
    json!({
        "principal_id": identity.principal_id(),
        "trust_level": trust,
        "roles": identity.roles(),
        "groups": identity.groups(),
        "scopes": identity.scopes(),
        "attributes": attributes,
    })
}

/// Every event type, by name.
#[derive(Debug, Default)]
pub struct EventCatalog {
    types: Vec<Arc<EventType>>,
    by_name: HashMap<String, usize>,
    by_source_id: HashMap<String, Vec<usize>>,
    /// Retention bytes the event-log store has left for imported types
    /// after the configured ones; `None` when the store sets no bound.
    import_room: Option<u64>,
}

impl EventCatalog {
    /// A catalog with no types.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Compile every type `config` declares. `registry` resolves secret
    /// references and supplies transform plugins.
    pub async fn build(
        config: &AppConfig,
        keys: &EventsKeys,
        registry: &mcpg_plugin_host::PluginRegistry,
    ) -> anyhow::Result<Self> {
        let enabled = config.mcp.configurations.events.enabled_modes();
        let secrets = crate::config::SecretsSource::from_config(&config.gateway.secrets);
        let mut types = Vec::with_capacity(config.mcp.capabilities.events.len());
        for declared in &config.mcp.capabilities.events {
            let ty = compile(config, declared, &enabled, keys, registry, &secrets)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("mcp.capabilities.events[`{}`]: {e}", declared.name)
                })?;
            types.push(Arc::new(ty));
        }
        let events = &config.mcp.configurations.events;
        let configured: u64 = config
            .mcp
            .capabilities
            .events
            .iter()
            .map(|ty| ty.retention.max_bytes_or_default())
            .sum();
        let import_room =
            crate::config::events::EventStoreClass::of(events.log_store.as_ref(), &config.cluster)
                .log_budget_bytes(&config.cluster)
                .map(|budget| budget.saturating_sub(configured));
        Ok(Self {
            import_room,
            ..Self::from_types(types)
        })
    }

    /// Give every type the schema epoch `log` keeps for its schemas.
    /// Called on a catalog that was just built and is not shared yet.
    pub async fn assign_schema_epochs(&mut self, log: &super::log::EventLog) -> anyhow::Result<()> {
        for ty in &mut self.types {
            let epoch = log
                .schema_epoch(&ty.name, &ty.input_schema, &ty.payload_schema)
                .await
                .map_err(|e| anyhow::anyhow!("mcp.capabilities.events[`{}`]: {e}", ty.name))?;
            Arc::get_mut(ty)
                .ok_or_else(|| anyhow::anyhow!("a catalog being built is not shared"))?
                .schema_epoch = epoch;
        }
        Ok(())
    }

    /// A catalog over already compiled types.
    pub fn from_types(mut types: Vec<Arc<EventType>>) -> Self {
        types.sort_by(|a, b| a.name.cmp(&b.name));
        let by_name = types
            .iter()
            .enumerate()
            .map(|(i, t)| (t.name.clone(), i))
            .collect();
        let mut by_source_id: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, t) in types.iter().enumerate() {
            if let SourceSpec::Inbound(inbound) = &t.source {
                by_source_id
                    .entry(inbound.source_id.clone())
                    .or_default()
                    .push(i);
            }
        }
        Self {
            types,
            by_name,
            by_source_id,
            import_room: None,
        }
    }

    /// The type called `name`.
    pub fn get(&self, name: &str) -> Option<&Arc<EventType>> {
        self.by_name.get(name).map(|&i| &self.types[i])
    }

    /// The types inbound route `source_id` feeds, sorted by name, each with
    /// its inbound source.
    pub fn by_source_id(&self, source_id: &str) -> Vec<(&Arc<EventType>, &InboundSpec)> {
        self.by_source_id
            .get(source_id)
            .into_iter()
            .flatten()
            .filter_map(|&i| match &self.types[i].source {
                SourceSpec::Inbound(spec) => Some((&self.types[i], spec)),
                _ => None,
            })
            .collect()
    }

    /// Every type, sorted by name.
    pub fn types(&self) -> &[Arc<EventType>] {
        &self.types
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// The configured types alone, without those a federation imported.
    pub fn configured(&self) -> Self {
        Self {
            import_room: self.import_room,
            ..Self::from_types(
                self.types
                    .iter()
                    .filter(|ty| !matches!(ty.source, SourceSpec::Federation { .. }))
                    .cloned()
                    .collect(),
            )
        }
    }

    /// The types a plan that serves at most `limit` keeps of this catalog,
    /// with the names of those it leaves out: configured types before
    /// imported ones, each in name order. `None` when every type fits.
    pub fn within(&self, limit: usize) -> Option<(Self, Vec<String>)> {
        if self.types.len() <= limit {
            return None;
        }
        let (configured, imported): (Vec<_>, Vec<_>) = self
            .types
            .iter()
            .cloned()
            .partition(|ty| !matches!(ty.source, SourceSpec::Federation { .. }));
        let mut kept: Vec<Arc<EventType>> = configured.into_iter().chain(imported).collect();
        let left_out = kept
            .split_off(limit)
            .into_iter()
            .map(|ty| ty.name.clone())
            .collect();
        Some((
            Self {
                import_room: self.import_room,
                ..Self::from_types(kept)
            },
            left_out,
        ))
    }

    /// This catalog's types and `extra`.
    pub fn with_types(&self, extra: Vec<EventType>) -> Self {
        let mut types = self.types.clone();
        types.extend(extra.into_iter().map(Arc::new));
        Self {
            import_room: self.import_room,
            ..Self::from_types(types)
        }
    }

    /// The imported types this catalog can serve beside its own, compiled
    /// for the delivery modes `enabled`, their schema epochs still to
    /// assign. A type whose name a configured type already takes, whose
    /// retention the event-log store has no room left for, or that cannot
    /// be served, is left out with a warning.
    pub fn compile_federated(
        &self,
        federated: &[FederatedEventType],
        ctx: &ImportContext<'_>,
    ) -> Vec<EventType> {
        let mut compiled: Vec<EventType> = Vec::with_capacity(federated.len());
        let mut room = self.import_room;
        for imported in federated {
            if self.get(&imported.name).is_some()
                || compiled.iter().any(|ty| ty.name == imported.name)
            {
                tracing::warn!(
                    federation = %imported.federation,
                    event = %imported.name,
                    "an imported event type has the name of another type; not served"
                );
                continue;
            }
            let bytes = imported.retention.max_bytes_or_default();
            if let Some(left) = room {
                if bytes > left {
                    tracing::warn!(
                        federation = %imported.federation,
                        event = %imported.name,
                        retention_bytes = bytes,
                        room_bytes = left,
                        "the event-log store has no room left for an imported event type's \
                         retention; not served (lower the federation's events.retention.max_bytes \
                         or give log_store a store of its own)"
                    );
                    continue;
                }
                room = Some(left - bytes);
            }
            match compile_federated(imported, ctx) {
                Ok(ty) => compiled.push(ty),
                Err(error) => tracing::warn!(
                    federation = %imported.federation,
                    event = %imported.name,
                    error = %error,
                    "an imported event type cannot be served"
                ),
            }
        }
        compiled
    }
}

/// What decides how imported types are served and read.
pub struct ImportContext<'a> {
    /// The delivery modes the gateway enables.
    pub enabled: &'a [EventDeliveryMode],
    pub keys: &'a EventsKeys,
    /// Whether upstreams can deliver webhooks to this gateway: it has a
    /// public address.
    pub callbacks: bool,
}

/// A served type over an imported descriptor. Its occurrences come from
/// the gateway's own log, so it offers every delivery mode the gateway
/// enables whatever modes the upstream offers, and always replays.
fn compile_federated(
    imported: &FederatedEventType,
    ctx: &ImportContext<'_>,
) -> anyhow::Result<EventType> {
    use crate::config::federation::UpstreamEventDelivery;
    use crate::config::schema_safety::compile_checked;

    if !crate::config::events::is_event_name(&imported.name) {
        anyhow::bail!("`{}` is not a valid event name", imported.name);
    }
    let offers = |mode: DeliveryMode| imported.descriptor.delivery.contains(&mode);
    let webhook = ctx.callbacks && offers(DeliveryMode::Webhook);
    let mode = match imported.delivery {
        UpstreamEventDelivery::Webhook if webhook => UpstreamMode::Webhook,
        UpstreamEventDelivery::Webhook if !ctx.callbacks => anyhow::bail!(
            "webhook delivery needs a public address of this gateway: gateway.server.canonical_url, or a public tunnel"
        ),
        UpstreamEventDelivery::Push if offers(DeliveryMode::Push) => UpstreamMode::Push,
        UpstreamEventDelivery::Poll if offers(DeliveryMode::Poll) => UpstreamMode::Poll,
        UpstreamEventDelivery::Auto if webhook => UpstreamMode::Webhook,
        UpstreamEventDelivery::Auto if offers(DeliveryMode::Push) => UpstreamMode::Push,
        UpstreamEventDelivery::Auto if offers(DeliveryMode::Poll) => UpstreamMode::Poll,
        _ => anyhow::bail!("the upstream offers no delivery mode this federation reads"),
    };
    let enabled = ctx.enabled;
    let keys = ctx.keys;
    let input_schema = imported.descriptor.input_schema.clone();
    let payload_schema = imported.descriptor.payload_schema.clone();
    let input_validator = compile_checked(&input_schema, "inputSchema")?;
    let payload_validator = compile_checked(&payload_schema, "payloadSchema")?;
    let delivery: Vec<DeliveryMode> = [
        (EventDeliveryMode::Poll, DeliveryMode::Poll),
        (EventDeliveryMode::Push, DeliveryMode::Push),
        (EventDeliveryMode::Webhook, DeliveryMode::Webhook),
    ]
    .into_iter()
    .filter(|(mode, _)| enabled.contains(mode))
    .map(|(_, wire)| wire)
    .collect();
    if delivery.is_empty() {
        anyhow::bail!("no delivery mode is enabled");
    }
    let mut retention = imported.retention.clone();
    retention.max_bytes = Some(retention.max_bytes_or_default());
    let descriptor = json!({
        "name": imported.name,
        "description": imported.descriptor.description,
        "delivery": delivery,
        "inputSchema": input_schema,
        "payloadSchema": payload_schema,
    });
    let source_fingerprint = fingerprint(&json!({
        "federation": imported.federation,
        "upstream": imported.upstream_name,
        "mode": format!("{mode:?}"),
        "sharing": imported.sharing,
    }));
    Ok(EventType {
        name: imported.name.clone(),
        description: imported.descriptor.description.clone(),
        delivery,
        input_schema,
        payload_schema,
        input_validator,
        payload_validator,
        match_expr: None,
        match_program: None,
        transform: None,
        retention,
        replay: EventReplay::Log,
        always_on: false,
        source: SourceSpec::Federation {
            federation: imported.federation.clone(),
            upstream_name: imported.upstream_name.clone(),
            mode,
            sharing: imported.sharing,
        },
        source_key: keys.source_key(&imported.name, &SourceScope::Shared),
        descriptor_fingerprint: fingerprint(&descriptor),
        source_fingerprint,
        schema_epoch: 0,
    })
}

async fn compile(
    config: &AppConfig,
    declared: &EventTypeConfig,
    enabled: &[EventDeliveryMode],
    keys: &EventsKeys,
    registry: &mcpg_plugin_host::PluginRegistry,
    secrets: &crate::config::SecretsSource,
) -> anyhow::Result<EventType> {
    use crate::config::schema_safety::compile_checked;

    let declared_source = declared.source.get().ok_or_else(|| {
        anyhow::anyhow!(
            "source must name exactly one of `watch`, `inbound`, `resource` or `builtin`"
        )
    })?;
    // The schemas a payload-bearing source declares stand in for the ones
    // the type leaves out.
    let (source_input, source_payload) = match declared_source {
        EventSource::Watch(watch) => match &watch.event_type {
            Some(name) => {
                let (kind, source) = strategy_event_source(registry, &watch.strategy)?;
                let declared = declared_event_type(source.as_ref(), &kind, name)?;
                (declared.input_schema, declared.payload_schema)
            }
            None => (None, None),
        },
        EventSource::Builtin(builtin) => (None, Some(builtin.payload_schema())),
        _ => (None, None),
    };
    let input_schema = declared
        .input_schema
        .clone()
        .or(source_input)
        .unwrap_or_else(default_input_schema);
    let payload_schema = declared
        .payload_schema
        .clone()
        .or(source_payload)
        .unwrap_or_else(default_payload_schema);
    let input_validator = compile_checked(&input_schema, "input_schema")?;
    let payload_validator = compile_checked(&payload_schema, "payload_schema")?;
    let match_program = declared
        .match_expr
        .as_deref()
        .map(cel::Program::compile)
        .transpose()
        .map_err(|e| anyhow::anyhow!("match is not a valid CEL expression: {e}"))?;
    if let Some(transform) = &declared.transform
        && registry.transform_by_id(&transform.plugin).is_none()
    {
        anyhow::bail!(
            "transform.plugin `{}` is not a loaded transform plugin",
            transform.plugin
        );
    }
    let delivery: Vec<DeliveryMode> = [
        (EventDeliveryMode::Poll, DeliveryMode::Poll),
        (EventDeliveryMode::Push, DeliveryMode::Push),
        (EventDeliveryMode::Webhook, DeliveryMode::Webhook),
    ]
    .into_iter()
    .filter(|(mode, _)| declared.delivery.contains(mode) && enabled.contains(mode))
    .map(|(_, wire)| wire)
    .collect();

    // A watch plugin gets its spec as values, never as placeholders; the
    // resolved strategy also feeds the fingerprint, so a rotated secret
    // restarts the source.
    let resolved_watch = match declared_source {
        EventSource::Watch(watch) => Some(
            crate::config::resolver::resolve_watch_strategy(
                &watch.strategy,
                registry,
                secrets,
                "source.watch.strategy",
            )
            .await?,
        ),
        EventSource::Resource(uri) => match config
            .mcp
            .capabilities
            .resources
            .iter()
            .find(|b| b.uri.as_deref() == Some(uri))
            .and_then(|b| b.watch.as_ref())
        {
            Some(watch) => Some(
                crate::config::resolver::resolve_watch_strategy(
                    &watch.strategy,
                    registry,
                    secrets,
                    "source.resource watch.strategy",
                )
                .await?,
            ),
            None => None,
        },
        _ => None,
    };
    let source = match declared_source {
        EventSource::Builtin(builtin) => SourceSpec::Builtin(builtin),
        EventSource::Watch(watch) => {
            let config = crate::config::ResourceWatchConfig {
                strategy: resolved_watch
                    .clone()
                    .unwrap_or_else(|| watch.strategy.clone()),
                notification_filter: None,
            };
            let uri = watch_source_uri(&declared.name);
            match crate::runtime::util::watch_config_for(&config, &uri).strategy {
                WatchStrategy::Plugin { kind, spec } => {
                    let source = registry
                        .watch_strategy(&kind)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "the source's watch strategy `{kind}` has no loaded watch plugin"
                            )
                        })?
                        .event_source();
                    let payload = match &watch.event_type {
                        Some(name) => Some(WatchPayload {
                            event_type: declared_event_type(source.as_ref(), &kind, name)?.name,
                            resume: source.as_ref().is_some_and(|s| s.resume),
                        }),
                        None => None,
                    };
                    SourceSpec::Watch {
                        kind,
                        spec,
                        placement: source.map(|s| s.placement).unwrap_or_default(),
                        payload,
                    }
                }
                WatchStrategy::Poll { .. } | WatchStrategy::Webhook { .. } => {
                    anyhow::bail!("source.watch needs a plugin watch strategy")
                }
            }
        }
        EventSource::Resource(uri) => {
            let mut watch = config
                .mcp
                .capabilities
                .resources
                .iter()
                .find(|b| b.uri.as_deref() == Some(uri))
                .and_then(|b| b.watch.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("source.resource `{uri}` names no watched resource binding")
                })?;
            if let Some(strategy) = &resolved_watch {
                watch.strategy = strategy.clone();
            }
            let strategy = match crate::runtime::util::watch_config_for(&watch, uri).strategy {
                WatchStrategy::Poll { interval_ms } => ResourceStrategy::Poll { interval_ms },
                WatchStrategy::Plugin { kind, spec } => {
                    // A resource source runs on the events owner alone, and
                    // such a watch sees only what reaches the owner.
                    let every_replica = registry
                        .watch_strategy(&kind)
                        .and_then(|plugin| plugin.event_source())
                        .is_some_and(|source| {
                            source.placement == mcpg_plugin_protocol::EventPlacement::EveryReplica
                        });
                    if every_replica {
                        anyhow::bail!(
                            "source.resource: the `{kind}` watch runs on every replica, where \
                             its upstream reaches; bind it as source.watch"
                        );
                    }
                    ResourceStrategy::Plugin { kind, spec }
                }
                WatchStrategy::Webhook { .. } => {
                    anyhow::bail!("source.resource: a webhook-token watch is not an event source")
                }
            };
            SourceSpec::Resource {
                uri: uri.to_owned(),
                strategy,
            }
        }
        EventSource::Inbound(inbound) => {
            let resolve = |raw: String| async move {
                crate::config::resolver::resolve_config_string(&raw, registry, secrets).await
            };
            let verifier = InboundVerifier::build(
                inbound,
                &config.mcp.configurations.events.inbound_profiles,
                resolve,
            )
            .await?;
            // The route's own pointers take the place of its profile's.
            let event_id_pointer = inbound
                .event_id
                .clone()
                .or_else(|| verifier.event_id_pointer().map(str::to_owned));
            let timestamp_pointer = inbound
                .timestamp
                .clone()
                .or_else(|| verifier.event_time_pointer().map(str::to_owned));
            SourceSpec::Inbound(InboundSpec {
                source_id: inbound.source_id.clone(),
                verifier,
                filter: InboundFilter::from_config(inbound)?,
                event_id_pointer,
                timestamp_pointer,
                rate: RateLimiter::new(&inbound.rate_limit),
            })
        }
    };

    if let SourceSpec::Watch { kind, .. }
    | SourceSpec::Resource {
        strategy: ResourceStrategy::Plugin { kind, .. },
        ..
    } = &source
        && registry.watch_strategy(kind).is_none()
    {
        anyhow::bail!("the source's watch strategy `{kind}` has no loaded watch plugin");
    }

    let mut retention = declared.retention.clone();
    retention.max_bytes = Some(retention.max_bytes_or_default());
    let source_key = keys.source_key(&declared.name, &SourceScope::Shared);
    let descriptor = json!({
        "name": declared.name,
        "description": declared.description,
        "delivery": delivery,
        "inputSchema": input_schema,
        "payloadSchema": payload_schema,
    });
    let source_fingerprint = fingerprint(&json!({
        "source": declared.source,
        "resource_watch": match declared_source {
            EventSource::Resource(uri) => config
                .mcp
                .capabilities
                .resources
                .iter()
                .find(|b| b.uri.as_deref() == Some(uri))
                .and_then(|b| serde_json::to_value(&b.watch).ok()),
            _ => None,
        },
        "resolved": resolved_watch
            .as_ref()
            .and_then(|strategy| serde_json::to_value(strategy).ok())
            .map(|value| fingerprint(&value)),
    }));
    Ok(EventType {
        name: declared.name.clone(),
        description: declared.description.clone(),
        delivery,
        input_schema,
        payload_schema,
        input_validator,
        payload_validator,
        match_expr: declared.match_expr.clone(),
        match_program,
        transform: declared.transform.clone(),
        retention,
        replay: declared.replay,
        always_on: declared.always_on,
        source,
        source_key,
        descriptor_fingerprint: fingerprint(&descriptor),
        source_fingerprint,
        schema_epoch: 0,
    })
}

fn fingerprint(value: &Value) -> String {
    hex::encode(Sha256::digest(canonical_value_bytes(value)))
}

/// The plugin kind `strategy` runs, and that strategy's descriptor entry.
fn strategy_event_source(
    registry: &mcpg_plugin_host::PluginRegistry,
    strategy: &crate::config::WatchStrategyConfig,
) -> anyhow::Result<(
    String,
    Option<mcpg_plugin_protocol::WatchStrategyDescriptor>,
)> {
    let config = crate::config::ResourceWatchConfig {
        strategy: strategy.clone(),
        notification_filter: None,
    };
    let WatchStrategy::Plugin { kind, .. } = crate::runtime::util::watch_config_for(
        &config,
        mcpg_plugin_protocol::EVENT_SOURCE_URI_PREFIX,
    )
    .strategy
    else {
        anyhow::bail!("source.watch needs a plugin watch strategy");
    };
    let plugin = registry.watch_strategy(&kind).ok_or_else(|| {
        anyhow::anyhow!("the source's watch strategy `{kind}` has no loaded watch plugin")
    })?;
    let source = plugin.event_source();
    Ok((kind, source))
}

/// The event type `name` that watch strategy `kind` declares in `source`,
/// its plugin's descriptor entry. A strategy that declares none is refused,
/// so it is never read as a source of empty events.
fn declared_event_type(
    source: Option<&mcpg_plugin_protocol::WatchStrategyDescriptor>,
    kind: &str,
    name: &str,
) -> anyhow::Result<mcpg_plugin_protocol::EventTypeDescriptor> {
    let declared = source.map(|s| s.event_types.as_slice()).unwrap_or_default();
    if declared.is_empty() {
        anyhow::bail!(
            "source.watch.event_type `{name}`: the `{kind}` watch strategy declares no event \
             types in its plugin's watch_strategies; rebuild the plugin with a release that does"
        );
    }
    declared
        .iter()
        .find(|t| t.name == name)
        .cloned()
        .ok_or_else(|| {
            let names: Vec<&str> = declared.iter().map(|t| t.name.as_str()).collect();
            anyhow::anyhow!(
                "source.watch.event_type `{name}` is not an event type of the `{kind}` watch \
                 strategy, which declares: {}",
                names.join(", ")
            )
        })
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
