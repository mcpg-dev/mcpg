//! The gateway builds every occurrence; nothing a source sends is passed
//! through as is.
//!
//! The event id becomes the `webhook-id` header of a delivery, so it is
//! limited to a header-safe alphabet without `.`; an id outside it is
//! replaced by a hash.
//! The time is normalized to RFC 3339 UTC. `data` goes through the type's
//! operator transform, must match the payload schema, has credential-shaped
//! values redacted, and must fit the size cap. An occurrence that fails a
//! step is dropped and counted, never delivered half-checked.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::catalog::EventType;

/// Longest event id kept as the source sent it.
pub const MAX_EVENT_ID_CHARS: usize = 128;
/// Prefix of an event id the gateway derives from an unusable one.
pub const DERIVED_EVENT_ID_PREFIX: &str = "evt_";

/// An occurrence as a source reports it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawOccurrence {
    /// The source's own id for the event, when it has one.
    pub event_id: Option<String>,
    /// When the event happened, RFC 3339, when the source knows.
    pub timestamp: Option<String>,
    /// The event's data.
    pub data: Value,
    /// The only principal it may reach, as a keyed hash of its key.
    pub audience: Option<String>,
    /// The only subscription arguments it answers, as their keyed hash
    /// ([`super::keys::EventsKeys::arguments_hash`]): an upstream
    /// subscription made with those arguments reported it.
    pub arguments: Option<String>,
    /// The source's position after this event, kept to resume from.
    pub upstream_cursor: Option<Value>,
}

/// An occurrence as the log keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredOccurrence {
    /// Stable id: the `webhook-id` of every delivery of this occurrence.
    pub event_id: String,
    /// RFC 3339 UTC time the event happened.
    pub timestamp: String,
    /// The shaped data.
    pub data: Value,
    /// When set, only the subscriptions of the principal whose keyed key
    /// hash this is receive the occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// When set, only subscriptions whose arguments have this keyed hash
    /// receive the occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

impl StoredOccurrence {
    /// Whether a reader with principal hash `audience` and arguments hash
    /// `arguments` receives this occurrence.
    pub fn is_for(&self, audience: &str, arguments: &str) -> bool {
        self.audience.as_deref().is_none_or(|a| a == audience)
            && self.arguments.as_deref().is_none_or(|a| a == arguments)
    }
}

/// Why an occurrence was dropped. Carries no event value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeError {
    /// The operator transform failed or its plugin is not loaded.
    Transform,
    /// The data does not match the type's payload schema.
    PayloadSchema,
    /// The occurrence is larger than `webhook.max_payload_bytes`.
    TooLarge { bytes: usize },
}

impl ShapeError {
    /// A bounded label for metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Transform => "transform",
            Self::PayloadSchema => "payload_schema",
            Self::TooLarge { .. } => "too_large",
        }
    }
}

/// Whether `id` may be used as an event id as it is: header-safe, free of
/// the `.` Standard Webhooks forbids in a `webhook-id`, and not in the
/// `msg_` space a receiver tells control envelopes apart by.
pub fn is_header_safe_event_id(id: &str) -> bool {
    use crate::protocol::v_2026_07_28::extensions::events::wire::CONTROL_WEBHOOK_ID_PREFIX;
    !id.is_empty()
        && id.len() <= MAX_EVENT_ID_CHARS
        && !id.starts_with(CONTROL_WEBHOOK_ID_PREFIX)
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
}

/// The event id of an occurrence of `type_name` from `source` that the
/// source called `upstream`: `upstream` itself when it is header-safe,
/// else a hash of all three; a fresh UUIDv7 when the source gave none.
pub fn event_id_for(type_name: &str, source: &str, upstream: Option<&str>) -> String {
    match upstream {
        Some(id) if is_header_safe_event_id(id) => id.to_owned(),
        Some(id) => {
            let mut hasher = Sha256::new();
            for part in [type_name, source, id] {
                hasher.update((part.len() as u64).to_be_bytes());
                hasher.update(part.as_bytes());
            }
            format!(
                "{DERIVED_EVENT_ID_PREFIX}{}",
                &hex::encode(hasher.finalize())[..32]
            )
        }
        None => uuid::Uuid::now_v7().to_string(),
    }
}

/// `timestamp` as RFC 3339 UTC with milliseconds, or `now` when it is
/// absent or not RFC 3339.
pub fn normalize_timestamp(timestamp: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> String {
    timestamp
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or(now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The current time in the form occurrences carry.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Build the stored occurrence of `raw` for `ty`.
///
/// `registry` supplies the operator transform's plugin; `max_bytes` caps
/// the serialized occurrence.
pub async fn shape(
    ty: &EventType,
    raw: RawOccurrence,
    registry: Option<&mcpg_plugin_host::PluginRegistry>,
    max_bytes: u64,
) -> Result<StoredOccurrence, ShapeError> {
    let event_id = event_id_for(&ty.name, ty.source.kind(), raw.event_id.as_deref());
    let timestamp = normalize_timestamp(raw.timestamp.as_deref(), chrono::Utc::now());
    let mut data = raw.data;
    if let Some(transform) = &ty.transform {
        data = apply_transform(ty, transform, data, registry).await?;
    }
    if !ty.payload_is_valid(&data) {
        return Err(ShapeError::PayloadSchema);
    }
    let data = crate::runtime::redact::redact_credentials(&data);
    let occurrence = StoredOccurrence {
        event_id,
        timestamp,
        data,
        audience: raw.audience,
        arguments: raw.arguments,
    };
    let bytes = serde_json::to_vec(&occurrence)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if bytes as u64 > max_bytes {
        return Err(ShapeError::TooLarge { bytes });
    }
    Ok(occurrence)
}

async fn apply_transform(
    ty: &EventType,
    transform: &crate::config::events::EventTransformConfig,
    data: Value,
    registry: Option<&mcpg_plugin_host::PluginRegistry>,
) -> Result<Value, ShapeError> {
    let plugin = registry
        .and_then(|r| r.transform_by_id(&transform.plugin))
        .ok_or(ShapeError::Transform)?;
    let ctx = mcpg_plugin_protocol::PluginContext {
        request_id: uuid::Uuid::now_v7().to_string(),
        session_id: None,
        tool_name: ty.name.clone(),
        surface: "event".to_owned(),
        identity: crate::runtime::util::plugin_identity_from_request_identity(
            &crate::runtime::RequestIdentity::Anonymous {
                source: "events".to_owned(),
            },
        ),
        transport: "internal".to_owned(),
    };
    let config = serde_json::json!({ "expression": transform.expression });
    match plugin.transform_result(&ctx, &data, &config).await {
        mcpg_plugin_protocol::TransformResult::Modified { value } => Ok(value),
        mcpg_plugin_protocol::TransformResult::Unchanged => Ok(data),
        mcpg_plugin_protocol::TransformResult::Error { .. } => Err(ShapeError::Transform),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_safe_ids_are_kept() {
        for id in ["a", "delivery-1", "orders:0:17", "x_y-z:1-2"] {
            assert!(is_header_safe_event_id(id), "{id}");
            assert_eq!(event_id_for("t", "inbound", Some(id)), id);
        }
    }

    #[test]
    fn unsafe_ids_are_replaced_by_a_stable_hash() {
        let long = "a".repeat(129);
        for bad in [
            "",
            "has space",
            "crlf\r\nInjected: 1",
            "slash/id",
            long.as_str(),
            "é",
            "msg_gap_abc",
            "x.y_z:1-2",
            "orders.v1:0:17",
        ] {
            assert!(!is_header_safe_event_id(bad), "{bad:?}");
            let derived = event_id_for("orders", "inbound", Some(bad));
            assert!(derived.starts_with("evt_"), "{derived}");
            assert_eq!(derived.len(), 4 + 32);
            assert!(is_header_safe_event_id(&derived));
            assert_eq!(derived, event_id_for("orders", "inbound", Some(bad)));
        }
        assert_ne!(
            event_id_for("orders", "inbound", Some("a b")),
            event_id_for("orders2", "inbound", Some("a b"))
        );
        assert_ne!(
            event_id_for("ab", "c", Some(" ")),
            event_id_for("a", "bc", Some(" "))
        );
    }

    #[test]
    fn a_dotted_id_hashes_to_the_same_id_on_every_replica_and_release() {
        // A Kafka id `topic:partition:offset` whose topic has a dot. Dedup
        // across replicas and restarts compares this exact value.
        let derived = event_id_for("orders.created", "watch", Some("orders.v1:0:17"));
        assert_eq!(derived, "evt_b556e04606cac0bcbcdc3e82ce83ef8e");
        assert!(!derived.contains('.'));
    }

    #[test]
    fn a_missing_id_is_a_fresh_uuid_v7() {
        let a = event_id_for("t", "watch", None);
        let b = event_id_for("t", "watch", None);
        assert_ne!(a, b);
        assert!(is_header_safe_event_id(&a));
        assert_eq!(uuid::Uuid::parse_str(&a).unwrap().get_version_num(), 7);
    }

    #[test]
    fn timestamps_are_normalized_to_utc() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-03T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            normalize_timestamp(Some("2026-10-03T14:30:00+02:00"), now),
            "2026-10-03T12:30:00.000Z"
        );
        assert_eq!(normalize_timestamp(None, now), "2026-10-03T12:00:00.000Z");
        assert_eq!(
            normalize_timestamp(Some("yesterday"), now),
            "2026-10-03T12:00:00.000Z"
        );
    }

    use crate::runtime::events::catalog::EventCatalog;
    use crate::runtime::events::test_support::{
        SESSION_KEY, WRAP_TRANSFORM, keys, transform_registry,
    };
    use serde_json::json;

    async fn catalog(registry: &mcpg_plugin_host::PluginRegistry) -> EventCatalog {
        let yaml = format!(
            r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    events:
      - name: plain
        payload_schema: {{ type: object, required: [n], properties: {{ n: {{ type: integer }} }} }}
        source: {{ inbound: {{ source_id: plain, allow_unsigned: true }} }}
      - name: wrapped
        payload_schema: {{ type: object, required: [wrapped] }}
        transform: {{ plugin: {WRAP_TRANSFORM}, expression: wrap }}
        source: {{ inbound: {{ source_id: wrapped, allow_unsigned: true }} }}
      - name: failing
        transform: {{ plugin: {WRAP_TRANSFORM}, expression: fail }}
        source: {{ inbound: {{ source_id: failing, allow_unsigned: true }} }}
"#
        );
        let config = crate::config::AppConfig::load_from_yaml_str(&yaml).unwrap();
        EventCatalog::build(&config, &keys(), registry)
            .await
            .unwrap()
    }

    fn raw(data: Value) -> RawOccurrence {
        RawOccurrence {
            event_id: Some("up-1".to_owned()),
            timestamp: Some("2026-10-03T14:30:00+02:00".to_owned()),
            data,
            ..RawOccurrence::default()
        }
    }

    #[tokio::test]
    async fn shaping_keeps_a_safe_id_normalizes_time_and_redacts_credentials() {
        let (registry, _) = transform_registry();
        let catalog = catalog(&registry).await;
        let plain = catalog.get("plain").unwrap();
        let shaped = shape(
            plain,
            raw(json!({"n": 1, "token": "abc", "note": "Bearer eyJhbGciOi"})),
            Some(&registry),
            245_760,
        )
        .await
        .unwrap();
        assert_eq!(shaped.event_id, "up-1");
        assert_eq!(shaped.timestamp, "2026-10-03T12:30:00.000Z");
        assert_eq!(
            shaped.data,
            json!({"n": 1, "token": "[redacted]", "note": "[redacted]"})
        );
    }

    #[tokio::test]
    async fn shaping_drops_what_fails_the_schema_or_the_size_cap() {
        let (registry, _) = transform_registry();
        let catalog = catalog(&registry).await;
        let plain = catalog.get("plain").unwrap();
        assert_eq!(
            shape(plain, raw(json!({"n": "one"})), Some(&registry), 245_760).await,
            Err(ShapeError::PayloadSchema)
        );
        assert_eq!(
            shape(plain, raw(json!({})), Some(&registry), 245_760).await,
            Err(ShapeError::PayloadSchema)
        );
        let big = json!({"n": 1, "pad": "x".repeat(1_000)});
        assert!(matches!(
            shape(plain, raw(big), Some(&registry), 500).await,
            Err(ShapeError::TooLarge { bytes }) if bytes > 1_000
        ));
        assert_eq!(ShapeError::PayloadSchema.label(), "payload_schema");
    }

    #[tokio::test]
    async fn the_transform_runs_on_the_event_surface_before_the_schema_check() {
        let (registry, calls) = transform_registry();
        let catalog = catalog(&registry).await;
        let wrapped = catalog.get("wrapped").unwrap();
        let shaped = shape(wrapped, raw(json!({"id": 1})), Some(&registry), 245_760)
            .await
            .unwrap();
        assert_eq!(shaped.data, json!({"wrapped": {"id": 1}}));
        assert_eq!(
            calls.lock().clone(),
            vec![(
                "event".to_owned(),
                "wrapped".to_owned(),
                json!({"expression": "wrap"})
            )]
        );

        let failing = catalog.get("failing").unwrap();
        assert_eq!(
            shape(failing, raw(json!({})), Some(&registry), 245_760).await,
            Err(ShapeError::Transform)
        );
        assert_eq!(
            shape(wrapped, raw(json!({})), None, 245_760).await,
            Err(ShapeError::Transform),
            "no registry, no transform: the occurrence is dropped, never passed through"
        );
    }
}
