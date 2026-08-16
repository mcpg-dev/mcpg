//! Per-binding resource-watch configuration. Used by binding configs
//! that produce `notifications/resources/updated` for subscribed
//! sessions.

use serde::{Deserialize, Serialize};

/// Per-binding resource watch configuration.
/// Defines how changes to a resource are detected for `notifications/resources/updated`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
pub struct ResourceWatchConfig {
    /// Strategy for detecting resource changes.
    #[serde(default)]
    pub strategy: WatchStrategyConfig,
    /// Notification filter — controls which subscribers receive the
    /// `notifications/resources/updated` message when a change is detected.
    /// Defaults to fan-out to all subscribers when absent.
    #[serde(default)]
    pub notification_filter: Option<NotificationFilterConfig>,
}

/// Scoping filter for resource change notifications. Determines which
/// subscribers receive `notifications/resources/updated` when the watch
/// engine detects a change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum NotificationFilterConfig {
    /// Fan-out to all subscribers (default, no filter).
    All,
    /// Only notify subscribers whose `principal_id` matches the event's user context.
    SubjectId,
    /// Only notify the originating session.
    SessionId,
    /// CEL expression evaluated per subscriber. Variables: `subscriber.principal_id`,
    /// `subscriber.trust_level`, `subscriber.roles`, `subscriber.groups`,
    /// `subscriber.scopes`, `subscriber.attributes`, `event.uri`.
    Expression { expression: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum WatchStrategyConfig {
    /// Poll the resource periodically and compare SHA-256 hash.
    Poll {
        #[serde(default = "default_poll_interval_ms")]
        interval_ms: u64,
    },
    /// Subscribe to a NATS subject — any message means the resource changed.
    NatsTopic { subject: String },
    /// Subscribe to a Kafka topic — any message means the resource changed.
    KafkaTopic {
        topic: String,
        #[serde(default = "default_kafka_watch_group_id")]
        group_id: String,
    },
    /// Receive webhook POSTs from 3rd-party systems.
    /// MCPG exposes `/webhooks/resource-updated/{token}` and triggers
    /// `notifications/resources/updated` when a POST is received.
    Webhook {
        /// Shared secret token that must appear in the URL path.
        /// If empty, a random UUID-v4 is generated on startup.
        #[serde(default)]
        token: String,
        /// Tokens still accepted while senders migrate to `token`.
        ///
        /// A sender is re-registered out of band and cannot be switched at
        /// the same instant the gateway is, so rotating a single token drops
        /// every event in between. Carrying the old value here keeps both
        /// live for one deploy: promote the new token, re-register senders,
        /// then empty this list.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        previous_tokens: Vec<String>,
    },
    /// SQL polling watch — `dev.mcpg.watch.sql_polling` plugin runs a
    /// scalar tracking query on a cadence and emits an event when the
    /// returned scalar advances. Spec mirrors the `[bindings.sql]`
    /// shape (`driver`, `url`, optional `pool` / `session_vars`,
    /// required `query` block, `interval_ms`); see the SQL binding
    /// plugin docs for the full field list. Pass-through here keeps
    /// the spec the single source of truth in the plugin crate.
    SqlPolling {
        /// Plugin spec — fields are flattened so YAML stays flat
        /// alongside `type: sql_polling`.
        #[serde(flatten)]
        #[schemars(with = "serde_json::Value")]
        spec: serde_json::Map<String, serde_json::Value>,
    },
    /// Postgres LISTEN/NOTIFY watch —
    /// `dev.mcpg.watch.postgres_listen_notify` plugin holds one
    /// dedicated connection per watch and re-emits NOTIFY payloads.
    /// Far lower overhead than polling for change-feed-style sources.
    PostgresListenNotify {
        /// Postgres connection URL. Credential interpolation via the
        /// gateway's `${env.VAR}` happens before the spec reaches the
        /// plugin.
        url: String,
        /// Channel name to LISTEN on (`NOTIFY <channel>, payload`).
        /// ASCII alphanumeric + underscore.
        channel: String,
    },
    /// Generic escape hatch — delegate to ANY loaded `watch_strategy`
    /// plugin by its `kind()` discriminator. Use this for custom watch
    /// plugins that have no dedicated typed variant above (e.g. the
    /// Twilio plugin's `twilio_inbound` strategy). The remaining fields
    /// flatten into the spec passed verbatim to the plugin's `watch()`,
    /// so the plugin owns and validates its own spec schema.
    ///
    /// `{ type: plugin, kind: twilio_inbound, kinds: [sms, voice] }`
    Plugin {
        /// The target plugin's `WatchStrategyPlugin::kind()` string.
        kind: String,
        /// Spec forwarded verbatim to the plugin (it owns the schema).
        #[serde(flatten)]
        #[schemars(with = "serde_json::Value")]
        spec: serde_json::Map<String, serde_json::Value>,
    },
}

fn default_poll_interval_ms() -> u64 {
    60000
}

fn default_kafka_watch_group_id() -> String {
    "mcpg-resource-watcher".to_owned()
}

impl Default for WatchStrategyConfig {
    fn default() -> Self {
        Self::Poll {
            interval_ms: default_poll_interval_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_strategy_parses_kind_and_flattens_spec() {
        // The generic escape hatch: `type: plugin` selects the variant, `kind`
        // names the target watch plugin, and the rest flattens into the spec
        // forwarded verbatim to the plugin.
        let cfg: WatchStrategyConfig =
            serde_yaml::from_str("type: plugin\nkind: twilio_inbound\nkinds: [sms, voice]\n")
                .expect("parses");
        match cfg {
            WatchStrategyConfig::Plugin { kind, spec } => {
                assert_eq!(kind, "twilio_inbound");
                assert_eq!(
                    spec.get("kinds").and_then(|v| v.as_array()).map(Vec::len),
                    Some(2)
                );
                assert!(
                    !spec.contains_key("kind"),
                    "kind is a typed field, not part of spec"
                );
                assert!(
                    !spec.contains_key("type"),
                    "type is the tag, not part of spec"
                );
            }
            other => panic!("expected Plugin, got {other:?}"),
        }
    }
}
