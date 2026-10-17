use super::*;
use crate::config::AppConfig;

/// Standard base64 of the bytes 0..32.
const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const HMAC_SOURCE: &str = r#"
        source:
          inbound:
            source_id: gh
            verify: { profile: github, secrets: [s3cr3t] }"#;

/// A config with events on, a durable store, a stable key, and `types`
/// (YAML list items at the `events:` indentation) under
/// `mcp.capabilities.events`.
fn config_with(types: &str) -> String {
    format!(
        r#"
mcp:
  configurations:
    sessions:
      synthetic_session_key: "{KEY}"
    events:
      enabled: true
      store: {{ kind: file, dir: /var/lib/mcpg/events }}
  capabilities:
    events:
{types}
"#
    )
}

fn load(yaml: &str) -> anyhow::Result<AppConfig> {
    AppConfig::load_from_yaml_str(yaml)
}

fn refused(yaml: &str) -> String {
    match load(yaml) {
        Ok(_) => panic!("expected a refusal for:\n{yaml}"),
        Err(error) => format!("{error:#}"),
    }
}

fn one_type(body: &str) -> String {
    config_with(&format!("      - name: gh.issue\n{body}"))
}

// ---------------------------------------------------------------------------
// mcp.configurations.events
// ---------------------------------------------------------------------------

#[test]
fn off_by_default_with_both_locations() {
    let config = EventsConfig::default();
    assert!(!config.enabled);
    assert!(!config.advertises_capability());
    assert!(!config.advertises_extension());
    assert_eq!(
        config.advertise,
        vec![
            EventsAdvertiseLocation::Capability,
            EventsAdvertiseLocation::Extension
        ]
    );
    config.validate().unwrap();

    let parsed: EventsConfig = serde_yaml::from_str("{}").unwrap();
    assert_eq!(parsed, config);
}

#[test]
fn defaults_follow_the_delivery_profile() {
    let config = EventsConfig::default();
    assert_eq!(config.unsubscribe_unknown, UnsubscribeUnknown::Ok);
    assert!(config.store.is_none() && config.log_store.is_none());
    assert!(!config.allow_ephemeral_subscriptions);
    assert_eq!(config.sources.linger_ms, 300_000);
    assert_eq!(config.log.inbox_ttl_ms, 86_400_000);
    assert_eq!(config.log.inbox_max_rows, 10_000);
    assert!(!config.delivery_paused);
    assert_eq!(config.reauthorize_interval_ms, 300_000);
    let webhook = &config.webhook;
    assert!(webhook.enabled);
    assert_eq!(webhook.require_trust, SubscriberTrust::Verified);
    assert_eq!(
        (
            webhook.ttl.default_ms,
            webhook.ttl.min_ms,
            webhook.ttl.max_ms
        ),
        (3_600_000, 300_000, 86_400_000)
    );
    assert!(!webhook.ttl.allow_no_expiry);
    assert!(webhook.ttl.clamp_to_token_expiry);
    assert_eq!(webhook.limits.per_principal, 100);
    assert_eq!(webhook.limits.per_principal_callback_hosts, 5);
    assert_eq!(webhook.limits.per_type, 5_000);
    assert_eq!(webhook.limits.total, 10_000);
    assert_eq!(
        webhook.verification.modes,
        vec![VerificationMode::Challenge]
    );
    assert_eq!(webhook.retry.max_attempts, 5);
    assert_eq!(webhook.retry.window_ms, 900_000);
    assert_eq!(webhook.suspension.failure_rate, FailureRate(0.95));
    assert_eq!(webhook.max_payload_bytes, 245_760);
    assert_eq!(webhook.max_payload_bytes, MAX_PAYLOAD_BYTES_CEILING);
    assert_eq!(
        webhook.control_envelopes,
        vec![ControlEnvelopeKind::Gap, ControlEnvelopeKind::Terminated]
    );
    assert!(!config.poll.enabled && !config.push.enabled);
    assert_eq!(config.enabled_modes(), vec![EventDeliveryMode::Webhook]);
}

#[test]
fn enabled_advertises_where_configured() {
    let both: EventsConfig = serde_yaml::from_str("enabled: true").unwrap();
    both.validate().unwrap();
    assert!(both.advertises_capability());
    assert!(both.advertises_extension());

    let extension_only: EventsConfig =
        serde_yaml::from_str("enabled: true\nadvertise: [extension]").unwrap();
    extension_only.validate().unwrap();
    assert!(!extension_only.advertises_capability());
    assert!(extension_only.advertises_extension());

    let capability_only: EventsConfig =
        serde_yaml::from_str("enabled: true\nadvertise: [capability]").unwrap();
    assert!(capability_only.advertises_capability());
    assert!(!capability_only.advertises_extension());
}

#[test]
fn enabled_with_nowhere_to_advertise_is_refused() {
    let nowhere: EventsConfig = serde_yaml::from_str("enabled: true\nadvertise: []").unwrap();
    let error = nowhere.validate().unwrap_err().to_string();
    assert!(error.contains("advertise"), "{error}");

    let disabled: EventsConfig = serde_yaml::from_str("advertise: []").unwrap();
    disabled.validate().unwrap();
}

#[test]
fn unknown_fields_and_locations_are_refused() {
    assert!(serde_yaml::from_str::<EventsConfig>("enabled: true\nbogus: 1").is_err());
    assert!(serde_yaml::from_str::<EventsConfig>("advertise: [server_card]").is_err());
    for nested in [
        "webhook: { bogus: 1 }",
        "webhook: { ttl: { bogus: 1 } }",
        "webhook: { limits: { bogus: 1 } }",
        "webhook: { verification: { bogus: 1 } }",
        "webhook: { egress: { bogus: 1 } }",
        "webhook: { retry: { bogus: 1 } }",
        "webhook: { suspension: { bogus: 1 } }",
        "webhook: { control_envelopes: [verification] }",
        "sources: { bogus: 1 }",
        "log: { bogus: 1 }",
        "audit: { deliveries: sometimes }",
        "poll: { bogus: 1 }",
        "push: { bogus: 1 }",
        "unsubscribe_unknown: maybe",
    ] {
        assert!(
            serde_yaml::from_str::<EventsConfig>(nested).is_err(),
            "{nested}"
        );
    }
}

/// The documented `mcp.configurations.events` block, every value spelled
/// out, is the defaults.
#[test]
fn the_documented_configuration_block_parses_and_validates() {
    let block = r#"
enabled: true
advertise: [capability, extension]
unsubscribe_unknown: ok
error_codes: draft
store: { kind: file, dir: /var/lib/mcpg/events }
log_store: { kind: file, dir: /var/lib/mcpg/events-log }
allow_ephemeral_subscriptions: false
delivery_paused: false
reauthorize_interval_ms: 300000
audit: { deliveries: summary }
sources: { linger_ms: 300000 }
log: { inbox_ttl_ms: 86400000, inbox_max_rows: 10000 }
webhook:
  enabled: true
  require_trust: verified
  ttl: { default_ms: 3600000, min_ms: 300000, max_ms: 86400000, allow_no_expiry: false, clamp_to_token_expiry: true }
  limits: { per_principal: 100, per_principal_callback_hosts: 5, per_type: 5000, total: 10000, per_host_concurrency: 8, per_subscription_in_flight: 4 }
  verification: { modes: [challenge], allowlist: [], cache_ttl_ms: 86400000, timeout_ms: 10000, per_host_per_min: 6, per_host_in_flight: 3 }
  egress: { allowed_ports: [], deny_hosts: [], connect_timeout_ms: 3000, attempt_timeout_ms: 10000, allow_private_backends: false }
  retry: { max_attempts: 5, window_ms: 900000, honor_retry_after: true }
  suspension: { failure_rate: 0.95, window_ms: 3600000, min_attempts: 100, drop_no_expiry_after_ms: 604800000 }
  max_payload_bytes: 245760
  secret_rotation_grace_ms: 600000
  control_envelopes: [gap, terminated]
poll: { enabled: false, require_trust: verified, next_poll_ms: 5000, min_next_poll_ms: 1000, max_events: 100, max_events_cap: 1000, lease_multiplier: 3, max_leases_per_principal: 100 }
push: { enabled: false, require_trust: verified, heartbeat_interval_ms: 20000, max_streams_per_principal: 16 }
"#;
    let parsed: EventsConfig = serde_yaml::from_str(block).unwrap();
    parsed.validate().unwrap();
    let mut expected = EventsConfig {
        enabled: true,
        ..EventsConfig::default()
    };
    expected.store = parsed.store.clone();
    expected.log_store = parsed.log_store.clone();
    assert_eq!(parsed, expected, "the documented values are the defaults");
}

#[test]
fn push_bounds_are_checked() {
    let parsed: EventsConfig = serde_yaml::from_str("push: { enabled: true }").unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.push.require_trust, SubscriberTrust::Verified);
    for (block, needle) in [
        (
            "push: { heartbeat_interval_ms: 999 }",
            "heartbeat_interval_ms",
        ),
        (
            "push: { heartbeat_interval_ms: 30001 }",
            "heartbeat_interval_ms",
        ),
        (
            "push: { max_streams_per_principal: 0 }",
            "max_streams_per_principal",
        ),
    ] {
        let parsed: EventsConfig = serde_yaml::from_str(block).unwrap();
        let error = parsed.validate().unwrap_err().to_string();
        assert!(error.contains(needle), "{block}: {error}");
    }
}

#[test]
fn poll_bounds_are_checked() {
    let parsed: EventsConfig = serde_yaml::from_str("poll: { enabled: true }").unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.poll.require_trust, SubscriberTrust::Verified);
    let cases = [
        ("poll: { min_next_poll_ms: 0 }", "min_next_poll_ms"),
        (
            "poll: { next_poll_ms: 500, min_next_poll_ms: 1000 }",
            "next_poll_ms",
        ),
        ("poll: { max_events: 0 }", "max_events"),
        ("poll: { max_events: 2000 }", "max_events_cap"),
        ("poll: { lease_multiplier: 0 }", "lease_multiplier"),
        (
            "poll: { max_leases_per_principal: 0 }",
            "max_leases_per_principal",
        ),
    ];
    for (block, needle) in cases {
        let parsed: EventsConfig = serde_yaml::from_str(block).unwrap();
        let error = parsed.validate().unwrap_err().to_string();
        assert!(error.contains(needle), "{block}: {error}");
    }
}

#[test]
fn webhook_bounds_are_checked() {
    let cases = [
        ("webhook: { ttl: { min_ms: 0 } }", "min_ms"),
        (
            "webhook: { ttl: { min_ms: 600000, default_ms: 300000 } }",
            "default_ms",
        ),
        ("webhook: { ttl: { max_ms: 1000 } }", "max_ms"),
        ("webhook: { limits: { per_principal: 0 } }", "per_principal"),
        (
            "webhook: { verification: { modes: [allowlist], allowlist: [h.example] } }",
            "challenge",
        ),
        (
            "webhook: { verification: { modes: [challenge, allowlist] } }",
            "allowlist",
        ),
        (
            "webhook: { verification: { modes: [challenge, allowlist], allowlist: ['https://h.example'] } }",
            "allowlist[0]",
        ),
        (
            "webhook: { egress: { connect_timeout_ms: 20000 } }",
            "connect_timeout_ms",
        ),
        (
            "webhook: { egress: { allowed_ports: [443, 0] } }",
            "allowed_ports",
        ),
        (
            "webhook: { egress: { deny_hosts: [' '] } }",
            "deny_hosts[0]",
        ),
        ("webhook: { retry: { max_attempts: 0 } }", "max_attempts"),
        (
            "webhook: { suspension: { failure_rate: 0.0 } }",
            "failure_rate",
        ),
        (
            "webhook: { suspension: { failure_rate: 1.5 } }",
            "failure_rate",
        ),
        ("webhook: { max_payload_bytes: 0 }", "max_payload_bytes"),
        (
            "webhook: { max_payload_bytes: 245761 }",
            "max_payload_bytes",
        ),
        ("reauthorize_interval_ms: 0", "reauthorize_interval_ms"),
        ("sources: { linger_ms: 0 }", "linger_ms"),
        ("log: { inbox_max_rows: 0 }", "inbox_max_rows"),
        ("store: { kind: file }", "store override"),
    ];
    for (block, needle) in cases {
        let parsed: EventsConfig = serde_yaml::from_str(block).unwrap();
        let error = parsed.validate().unwrap_err().to_string();
        assert!(error.contains(needle), "{block}: {error}");
    }
    for block in [
        "webhook: { suspension: { failure_rate: 1.0 } }",
        "webhook: { max_payload_bytes: 1 }",
        "webhook: { verification: { modes: [challenge, allowlist], allowlist: [hooks.example, 203.0.113.7] } }",
        "webhook: { ttl: { min_ms: 1000, default_ms: 1000, max_ms: 1000 } }",
    ] {
        let parsed: EventsConfig = serde_yaml::from_str(block).unwrap();
        parsed.validate().unwrap_or_else(|e| panic!("{block}: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Durability and keys
// ---------------------------------------------------------------------------

#[test]
fn webhook_delivery_refuses_a_store_that_forgets() {
    let memory = format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true }}
"#
    );
    assert!(refused(&memory).contains("allow_ephemeral_subscriptions"));

    let explicit_memory = format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true, store: {{ kind: memory }} }}
"#
    );
    assert!(refused(&explicit_memory).contains("in memory"));

    let opted_in = format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true, allow_ephemeral_subscriptions: true }}
"#
    );
    load(&opted_in).unwrap();

    let file = format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /var/lib/mcpg/events }} }}
"#
    );
    load(&file).unwrap();

    // Off, or with webhook delivery off, nothing is stored.
    load("mcp: { configurations: { events: { enabled: false } } }").unwrap();
    load("mcp: { configurations: { events: { enabled: true, webhook: { enabled: false } } } }")
        .unwrap();
}

#[test]
fn webhook_delivery_needs_a_shared_key() {
    let none = r#"
mcp:
  configurations:
    events: { enabled: true, store: { kind: file, dir: /var/lib/mcpg/events } }
"#;
    let error = refused(none);
    assert!(error.contains("state_encryption_key_env"), "{error}");
    assert!(error.contains("synthetic_session_key"), "{error}");

    let malformed = r#"
mcp:
  configurations:
    sessions: { synthetic_session_key: "c2hvcnQ=" }
    events: { enabled: true, store: { kind: file, dir: /var/lib/mcpg/events } }
"#;
    assert!(refused(malformed).contains("exactly 32 bytes"));

    // Without webhook delivery a single node may keep its keys to itself;
    // a cluster may not, or each replica reads its own cursors.
    let poll_only = |cluster: &str| {
        format!(
            r#"
{cluster}
mcp:
  configurations:
    events:
      enabled: true
      webhook: {{ enabled: false }}
      poll: {{ enabled: true }}
"#
        )
    };
    load(&poll_only("")).expect("a single node keeps its own key");
    let error = refused(&poll_only(
        "cluster: { kind: nats, url: \"nats://n.example:4222\", allow_plaintext_state: true }",
    ));
    assert!(error.contains("a clustered gateway"), "{error}");

    assert_eq!(
        decode_synthetic_session_key(KEY),
        Some(std::array::from_fn(|i| i as u8))
    );
    assert_eq!(decode_synthetic_session_key("not base64!"), None);
    assert_eq!(decode_synthetic_session_key("c2hvcnQ="), None);
}

#[test]
fn store_classes_decide_durability_and_log_budget() {
    let single = crate::config::ClusterConfig::default();
    assert!(single.is_single_node());
    let nats: crate::config::ClusterConfig =
        serde_yaml::from_str("kind: nats\nurl: nats://n.example:4222").unwrap();
    let store = |kind: &str| -> StoreOverrideConfig {
        serde_yaml::from_str(&format!("kind: {kind}\ndir: /x")).unwrap()
    };
    let memory: StoreOverrideConfig = serde_yaml::from_str("kind: memory").unwrap();
    let cluster: StoreOverrideConfig = serde_yaml::from_str("kind: cluster").unwrap();

    let cases = [
        (
            EventStoreClass::of(None, &single),
            EventStoreClass::SingleNodeCoordinator,
        ),
        (
            EventStoreClass::of(Some(&cluster), &single),
            EventStoreClass::SingleNodeCoordinator,
        ),
        (
            EventStoreClass::of(None, &nats),
            EventStoreClass::DistributedCoordinator,
        ),
        (
            EventStoreClass::of(Some(&cluster), &nats),
            EventStoreClass::DistributedCoordinator,
        ),
        (
            EventStoreClass::of(Some(&memory), &nats),
            EventStoreClass::Memory,
        ),
        (
            EventStoreClass::of(Some(&store("file")), &single),
            EventStoreClass::File,
        ),
        (
            EventStoreClass::of(Some(&store("dev.mcpg.kv.redis")), &single),
            EventStoreClass::Plugin,
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
    assert!(!EventStoreClass::SingleNodeCoordinator.is_durable());
    assert!(!EventStoreClass::Memory.is_durable());
    assert!(EventStoreClass::DistributedCoordinator.is_durable());
    assert!(EventStoreClass::File.is_durable());
    assert!(EventStoreClass::Plugin.is_durable());
    // On NATS the log shares the events bucket with the subscriptions.
    assert_eq!(
        EventStoreClass::DistributedCoordinator.log_budget_bytes(&nats),
        Some(128 * 1024 * 1024)
    );
    let small: crate::config::ClusterConfig = serde_yaml::from_str(
        "kind: nats\nurl: nats://n.example:4222\njetstream: { named_bucket_max_bytes: 67108864 }",
    )
    .unwrap();
    assert_eq!(
        EventStoreClass::DistributedCoordinator.log_budget_bytes(&small),
        Some(32 * 1024 * 1024)
    );
    let redis: crate::config::ClusterConfig =
        serde_yaml::from_str("kind: redis\nurl: rediss://r.example:6379").unwrap();
    assert_eq!(
        EventStoreClass::DistributedCoordinator.log_budget_bytes(&redis),
        None,
        "Redis bounds no store by size"
    );
    assert_eq!(
        EventStoreClass::SingleNodeCoordinator.log_budget_bytes(&single),
        Some(64 * 1024 * 1024)
    );
    assert_eq!(EventStoreClass::File.log_budget_bytes(&single), None);
    assert_eq!(EventStoreClass::Plugin.log_budget_bytes(&single), None);
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[test]
fn a_documented_inbound_type_loads() {
    let yaml = config_with(
        r#"      - name: github.issue.opened
        description: An issue was opened in a watched repository.
        input_schema: { type: object, properties: { repo: { type: string } }, required: [repo] }
        payload_schema: { type: object, properties: { number: { type: integer }, title: { type: string }, repo: { type: string } } }
        match: 'event.data.repo == arguments.repo'
        retention: { max_age_ms: 86400000, max_events: 10000, max_bytes: 8388608 }
        replay: log
        source:
          inbound:
            source_id: gh-issues
            verify: { profile: github, secrets: ["s3cr3t"] }
            timestamp: /issue/created_at
            when: { header: { X-GitHub-Event: issues }, body: { /action: opened } }
            rate_limit: { per_sec: 50, burst: 100 }"#,
    );
    let config = load(&yaml).unwrap();
    let ty = &config.mcp.capabilities.events[0];
    assert_eq!(ty.name, "github.issue.opened");
    assert_eq!(
        ty.delivery,
        vec![
            EventDeliveryMode::Poll,
            EventDeliveryMode::Push,
            EventDeliveryMode::Webhook
        ]
    );
    assert_eq!(ty.audience, EventAudience::Shared);
    assert_eq!(ty.replay, EventReplay::Log);
    assert!(!ty.always_on);
    let Some(EventSource::Inbound(inbound)) = ty.source.get() else {
        panic!("an inbound source");
    };
    assert_eq!(inbound.source_id, "gh-issues");
    assert_eq!(inbound.event_id, None);
    assert_eq!(
        inbound.verify,
        Some(InboundVerifyConfig {
            profile: "github".to_owned(),
            secrets: vec!["s3cr3t".to_owned()],
            tolerance_secs: None,
        })
    );
}

#[test]
fn a_documented_watch_type_loads_and_a_standard_webhooks_route_too() {
    let yaml = config_with(
        r#"      - name: orders.created
        description: A new order row was committed.
        delivery: [webhook]
        source:
          watch:
            strategy:
              type: kafka_topic
              topic: orders
              group_id: mcpg-events-orders
      - name: upstream.thing
        source:
          inbound:
            source_id: upstream
            verify: { profile: standard_webhooks, secrets: ["whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"], tolerance_secs: 60 }"#,
    );
    let config = load(&yaml).unwrap();
    assert_eq!(config.mcp.capabilities.events.len(), 2);
    let Some(EventSource::Inbound(inbound)) = config.mcp.capabilities.events[1].source.get() else {
        panic!("inbound");
    };
    assert!(matches!(
        &inbound.verify,
        Some(InboundVerifyConfig {
            profile,
            tolerance_secs: Some(60),
            ..
        }) if profile == "standard_webhooks"
    ));
}

#[test]
fn names_are_checked_and_unique() {
    for bad in ["", "has space", "slash/name", &"a".repeat(129)] {
        let yaml = config_with(&format!("      - name: '{bad}'{HMAC_SOURCE}"));
        assert!(refused(&yaml).contains("must be 1 to 128"), "{bad:?}");
    }
    assert!(is_event_name(&"a".repeat(128)));
    assert!(is_event_name("orders.created_v2-x"));

    let twice = config_with(&format!(
        "      - name: a{HMAC_SOURCE}\n      - name: a\n        source:\n          inbound:\n            source_id: other\n            allow_unsigned: true"
    ));
    assert!(refused(&twice).contains("duplicate event name"));
}

#[test]
fn a_name_under_a_federation_event_prefix_is_refused() {
    let with = |federation: &str| {
        format!(
            r#"
mcp:
  federations:
    - name: acme
      upstream: {{ url: "https://mcp.acme.example/mcp" }}
      {federation}
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    events:
      - name: acme.incident{HMAC_SOURCE}
"#
        )
    };
    let imported = with(
        r#"import: { events: true }
      naming: { event_prefix: "acme." }"#,
    );
    let error = refused(&imported);
    assert!(
        error.contains("starts with `acme.`") && error.contains("naming.event_prefix"),
        "{error}"
    );

    // A tool prefix names tools; a federation that imports no events
    // cannot clash with a local event type.
    load(&with(r#"naming: { tool_prefix: "acme." }"#)).expect("tool prefix only");
    load(&with(r#"naming: { event_prefix: "acme." }"#)).expect("no events imported");
}

#[test]
fn per_principal_audience_is_refused() {
    let yaml = one_type(&format!("        audience: per_principal{HMAC_SOURCE}"));
    assert!(refused(&yaml).contains("per_principal"));
}

#[test]
fn a_type_must_offer_an_enabled_mode() {
    let yaml = one_type(&format!("        delivery: [poll]{HMAC_SOURCE}"));
    assert!(refused(&yaml).contains("no mode"));
    let yaml = one_type(&format!("        delivery: []{HMAC_SOURCE}"));
    assert!(refused(&yaml).contains("at least one"));
    let yaml = one_type(&format!("        delivery: [poll, webhook]{HMAC_SOURCE}"));
    load(&yaml).unwrap();
}

#[test]
fn schemas_must_be_safe_object_schemas() {
    let cases = [
        ("input_schema: { type: string }", "object schema"),
        ("payload_schema: { type: array }", "object schema"),
        ("input_schema: { $schema_ref: shared }", "$schema_ref"),
        (
            "input_schema: { type: object, properties: { a: { $ref: 'https://evil.example/s.json' } } }",
            "input_schema",
        ),
        (
            "payload_schema: { type: object, properties: 5 }",
            "payload_schema",
        ),
    ];
    for (line, needle) in cases {
        let yaml = one_type(&format!("        {line}{HMAC_SOURCE}"));
        let error = refused(&yaml);
        assert!(error.contains(needle), "{line}: {error}");
    }
}

#[test]
fn match_must_compile() {
    let yaml = one_type(&format!("        match: 'event.data.repo =='{HMAC_SOURCE}"));
    assert!(refused(&yaml).contains("not a valid CEL expression"));
    let yaml = one_type(&format!(
        "        match: 'size(arguments) == 0'{HMAC_SOURCE}"
    ));
    load(&yaml).unwrap();
}

#[test]
fn transform_needs_plugin_and_expression() {
    let yaml = one_type(&format!(
        "        transform: {{ plugin: '', expression: 'x' }}{HMAC_SOURCE}"
    ));
    assert!(refused(&yaml).contains("transform"));
}

#[test]
fn retention_is_bounded() {
    let yaml = one_type(&format!(
        "        retention: {{ max_bytes: 1000 }}{HMAC_SOURCE}"
    ));
    assert!(refused(&yaml).contains("at least 262144"));
    let yaml = one_type(&format!(
        "        retention: {{ max_events: 0 }}{HMAC_SOURCE}"
    ));
    assert!(refused(&yaml).contains("max_events"));
}

#[test]
fn watch_sources_take_plugin_strategies_only() {
    for (strategy, needle) in [
        (
            "{ type: poll, interval_ms: 1000 }",
            "`poll` reads a resource",
        ),
        ("{ type: webhook, token: t }", "not an event source"),
        ("{ type: plugin, kind: '' }", "kind must not be empty"),
    ] {
        let yaml = one_type(&format!(
            "        source:\n          watch:\n            strategy: {strategy}"
        ));
        assert!(refused(&yaml).contains(needle), "{strategy}");
    }
    let yaml = one_type(
        "        source:\n          watch:\n            strategy: { type: nats_topic, subject: orders }\n            notification_filter: { scope: all }",
    );
    assert!(
        load(&yaml).is_err(),
        "a notification filter never applies to events"
    );
}

#[test]
fn a_watch_payload_schema_must_accept_the_tick() {
    let yaml = one_type(
        "        payload_schema: { type: object, required: [orderId] }\n        source:\n          watch:\n            strategy: { type: nats_topic, subject: orders }",
    );
    assert!(refused(&yaml).contains("{observedAt}"));
    let yaml = one_type(
        "        payload_schema: { type: object, properties: { observedAt: { type: string } }, additionalProperties: false }\n        source:\n          watch:\n            strategy: { type: nats_topic, subject: orders }",
    );
    load(&yaml).unwrap();
}

fn with_resource(watch: &str, types: &str) -> String {
    format!(
        r#"
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    resources:
      - name: report
        description: The nightly report.
        uri: "file:///data/report.csv"
        backend: {{ kind: mock, response: "x" }}
{watch}
    events:
{types}
"#
    )
}

#[test]
fn resource_sources_reuse_a_watched_binding() {
    let source = "      - name: report.changed\n        source:\n          resource: file:///data/report.csv";
    let polled = with_resource(
        "        watch: { strategy: { type: poll, interval_ms: 60000 } }",
        source,
    );
    load(&polled).unwrap();

    let unwatched = with_resource("", source);
    assert!(refused(&unwatched).contains("no `watch:` block"));

    let token = with_resource(
        "        watch: { strategy: { type: webhook, token: abc } }",
        source,
    );
    assert!(refused(&token).contains("token route"));

    let unknown = with_resource(
        "        watch: { strategy: { type: poll } }",
        "      - name: other\n        source:\n          resource: file:///nope",
    );
    assert!(refused(&unknown).contains("names no"));

    let strict = with_resource(
        "        watch: { strategy: { type: poll } }",
        "      - name: report.changed\n        payload_schema: { type: object, properties: { uri: { const: other } } }\n        source:\n          resource: file:///data/report.csv",
    );
    assert!(refused(&strict).contains("{uri, observedAt}"));
}

#[test]
fn inbound_sources_are_checked() {
    let cases = [
        (
            "        source:\n          inbound:\n            source_id: gh",
            "configure `verify`",
        ),
        (
            "        source:\n          inbound:\n            source_id: 'g h'\n            allow_unsigned: true",
            "source_id",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            verify: { profile: standard_webhooks, secrets: [] }",
            "at least one secret",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            verify: { profile: nobody, secrets: [x] }",
            "neither a built-in profile nor declared",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            verify: { profile: github, secrets: [x], tolerance_secs: 60 }",
            "signs no timestamp",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            verify: { profile: slack, secrets: [x], tolerance_secs: 0 }",
            "greater than 0",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            allow_unsigned: true\n            event_id: delivery_id",
            "JSON pointer",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            allow_unsigned: true\n            when: { body: { action: opened } }",
            "JSON pointer",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            allow_unsigned: true\n            rate_limit: { per_sec: 0 }",
            "per_sec",
        ),
        (
            "        source:\n          inbound:\n            source_id: gh\n            verify: { scheme: github, secrets: [x] }",
            "unknown field",
        ),
    ];
    for (body, needle) in cases {
        let error = refused(&one_type(body));
        assert!(error.contains(needle), "{body}: {error}");
    }
    load(&one_type(
        "        source:\n          inbound:\n            source_id: gh\n            allow_unsigned: true",
    ))
    .unwrap();

    let shared_route = config_with(&format!(
        "      - name: a{HMAC_SOURCE}\n      - name: b{HMAC_SOURCE}"
    ));
    load(&shared_route).unwrap();
    let other_secret = config_with(&format!(
        "      - name: a{HMAC_SOURCE}\n      - name: b{}",
        HMAC_SOURCE.replace("s3cr3t", "other")
    ));
    let error = refused(&other_secret);
    assert!(
        error.contains("route `gh` is shared with event type `a`"),
        "{error}"
    );
    let other_rate = config_with(&format!(
        "      - name: a{HMAC_SOURCE}\n      - name: b{HMAC_SOURCE}\n            rate_limit: {{ per_sec: 5 }}"
    ));
    assert!(refused(&other_rate).contains("declare the same three"));
}

#[test]
fn operator_profiles_are_checked_and_routes_can_name_them() {
    let with_profiles = |profiles: &str, verify: &str| {
        format!(
            r#"
mcp:
  configurations:
    sessions:
      synthetic_session_key: "{KEY}"
    events:
      enabled: true
      store: {{ kind: file, dir: /var/lib/mcpg/events }}
      inbound_profiles:
{profiles}
  capabilities:
    events:
      - name: acme.order
        source:
          inbound:
            source_id: acme
            verify: {verify}
"#
        )
    };
    let acme = "        - name: acme\n          signature: { header: X-Acme-Signature, encoding: base64 }\n          signed_payload: \"{timestamp}.{body}\"\n          signed_timestamp: { header: X-Acme-Time, tolerance_secs: 30 }";
    let config = load(&with_profiles(
        acme,
        "{ profile: acme, secrets: [k], tolerance_secs: 10 }",
    ))
    .unwrap();
    assert_eq!(
        config.mcp.configurations.events.inbound_profiles[0].name,
        "acme"
    );

    let cases = [
        (
            "        - name: github\n          signature: { header: X-Sig }",
            "is a built-in profile",
        ),
        (
            "        - name: Acme\n          signature: { header: X-Sig }",
            "[a-z0-9_-]",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n        - name: acme\n          signature: { header: X-Sig }",
            "duplicate profile name",
        ),
        (
            "        - name: acme\n          signature: { header: 'bad header' }",
            "not a valid header name",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig, encoding: utf8 }",
            "`hex` or `base64`",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig, key: v1 }",
            "needs signature.separator",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_payload: \"{timestamp}\"",
            "{body} exactly once",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_payload: \"{timestamp}.{body}\"",
            "no signed_timestamp",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_payload: \"{nonce}.{body}\"",
            "is not {body}, {timestamp} or {header:NAME}",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_payload: \"{body\"",
            "outside a placeholder",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_timestamp: { key: t }",
            "needs signature.key",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          signed_timestamp: { header: X-T, key: t }",
            "exactly one of `header` and `key`",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          event_id: { pointer: id }",
            "JSON pointer",
        ),
        (
            "        - name: acme\n          signature: { header: X-Sig }\n          handshakes: [ { when: {} } ]",
            "matches every request",
        ),
        (
            "        - name: acme\n          secret: { min_bytes: 0 }\n          signature: { header: X-Sig }",
            "secret.min_bytes must be at least 1",
        ),
        (
            "        - name: acme\n          secret: { max_bytes: 0 }\n          signature: { header: X-Sig }",
            "secret.max_bytes must be at least 1",
        ),
        (
            "        - name: acme\n          secret: { min_bytes: 33, max_bytes: 32 }\n          signature: { header: X-Sig }",
            "min_bytes (33) must not exceed secret.max_bytes (32)",
        ),
    ];
    for (profiles, needle) in cases {
        let error = refused(&with_profiles(profiles, "{ profile: acme, secrets: [k] }"));
        assert!(error.contains(needle), "{profiles}: {error}");
    }

    let bounded = load(&with_profiles(
        "        - name: acme\n          secret: { encoding: hex, min_bytes: 32, max_bytes: 32 }\n          signature: { header: X-Sig }",
        "{ profile: acme, secrets: [k] }",
    ))
    .unwrap();
    let secret = &bounded.mcp.configurations.events.inbound_profiles[0].secret;
    assert_eq!((secret.min_bytes, secret.max_bytes), (Some(32), Some(32)));
}

#[test]
fn exactly_one_source_is_named() {
    let two = one_type(
        "        source:\n          resource: x\n          inbound: { source_id: gh, allow_unsigned: true }",
    );
    assert!(refused(&two).contains("exactly one of"));
    let empty = one_type("        source: {}");
    assert!(refused(&empty).contains("exactly one of"));
    let missing = config_with("      - name: a");
    assert!(refused(&missing).contains("source"));
    let unknown = one_type("        source: { plugin: x }");
    assert!(load(&unknown).is_err());
}

#[test]
fn retention_budgets_must_fit_the_log_store() {
    let types = |n: usize| {
        (0..n)
            .map(|i| {
                format!(
                    "      - name: t{i}\n        source:\n          inbound: {{ source_id: s{i}, allow_unsigned: true }}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    // The single node's in-memory coordinator gives the log 64 MiB: eight
    // types at the 8 MiB default fit, nine do not.
    load(&config_with(&types(8))).unwrap();
    let error = refused(&config_with(&types(9)));
    assert!(error.contains("75497472 bytes"), "{error}");
    assert!(error.contains("log_store"), "{error}");

    // A file store sets no limit on the sum.
    let file_log = config_with(&types(9)).replace(
        "store: { kind: file, dir: /var/lib/mcpg/events }",
        "store: { kind: file, dir: /var/lib/mcpg/events }\n      log_store: { kind: file, dir: /var/lib/mcpg/log }",
    );
    load(&file_log).unwrap();

    // Smaller budgets fit more types.
    let small = config_with(
        &(0..20)
            .map(|i| {
                format!(
                    "      - name: t{i}\n        retention: {{ max_bytes: 1048576 }}\n        source:\n          inbound: {{ source_id: s{i}, allow_unsigned: true }}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );
    load(&small).unwrap();
}

#[test]
fn declarations_are_checked_even_while_events_are_off() {
    let yaml = r#"
mcp:
  capabilities:
    events:
      - name: 'bad name'
        source:
          inbound: { source_id: gh, allow_unsigned: true }
"#;
    assert!(refused(yaml).contains("must be 1 to 128"));
    let fine = r#"
mcp:
  capabilities:
    events:
      - name: ok
        delivery: [poll]
        source:
          inbound: { source_id: gh, allow_unsigned: true }
"#;
    load(fine).unwrap();
}

#[test]
fn the_tick_samples_are_what_the_sources_send() {
    assert_eq!(
        watch_tick_sample(),
        serde_json::json!({ "observedAt": "2026-01-01T00:00:00Z" })
    );
    assert_eq!(
        resource_tick_sample("file:///x")["uri"],
        serde_json::json!("file:///x")
    );
    assert!(is_source_id("gh-issues_2"));
    assert!(!is_source_id("gh.issues"));
    assert!(!is_source_id(&"a".repeat(65)));
}
