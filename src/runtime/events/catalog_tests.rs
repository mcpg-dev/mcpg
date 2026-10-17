use super::*;
use crate::runtime::events::test_support::{SESSION_KEY, ScriptedWatch, keys};
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::DeliveryMode;
use serde_json::json;

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
        watch: {{ strategy: {{ type: poll, interval_ms: 15000 }} }}
    events:
{types}
"#
    );
    AppConfig::load_from_yaml_str(&yaml).unwrap()
}

async fn build(types: &str, plugins: &[Arc<ScriptedWatch>]) -> anyhow::Result<EventCatalog> {
    EventCatalog::build(&config(types), &keys(), &ScriptedWatch::registry(plugins)).await
}

const INBOUND: &str = r#"      - name: gh.issue
        description: An issue was opened.
        source:
          inbound:
            source_id: gh
            verify: { profile: github, secrets: [s3cr3t] }"#;

#[tokio::test]
async fn an_inbound_type_compiles_to_its_descriptor() {
    let catalog = build(INBOUND, &[]).await.unwrap();
    assert_eq!(catalog.len(), 1);
    let ty = catalog.get("gh.issue").unwrap();
    let descriptor = ty.descriptor();
    assert_eq!(descriptor.name, "gh.issue");
    assert_eq!(
        descriptor.description.as_deref(),
        Some("An issue was opened.")
    );
    assert_eq!(descriptor.delivery, vec![DeliveryMode::Webhook]);
    assert_eq!(descriptor.input_schema, default_input_schema());
    assert_eq!(descriptor.payload_schema, default_payload_schema());
    assert_eq!(
        serde_json::to_value(&descriptor).unwrap(),
        json!({
            "name": "gh.issue",
            "description": "An issue was opened.",
            "delivery": ["webhook"],
            "inputSchema": {"type": "object", "additionalProperties": false},
            "payloadSchema": {"type": "object"},
        })
    );
    assert_eq!(ty.source.kind(), "inbound");
    assert!(!ty.source.needs_runner());
    assert_eq!(
        ty.source_key,
        keys().source_key("gh.issue", &SourceScope::Shared)
    );
    let route = catalog.by_source_id("gh");
    assert_eq!(route.len(), 1);
    assert!(Arc::ptr_eq(route[0].0, ty));
    assert!(catalog.by_source_id("other").is_empty());
    assert_eq!(ty.retention.max_bytes, Some(8 * 1024 * 1024));
    assert_eq!(ty.schema_epoch, 0);
}

#[tokio::test]
async fn types_are_sorted_by_name() {
    let catalog = build(
        r#"      - name: zeta
        source: { inbound: { source_id: z, allow_unsigned: true } }
      - name: alpha
        source: { inbound: { source_id: a, allow_unsigned: true } }
      - name: mid
        source: { inbound: { source_id: m, allow_unsigned: true } }"#,
        &[],
    )
    .await
    .unwrap();
    let names: Vec<&str> = catalog.types().iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["alpha", "mid", "zeta"]);
}

#[tokio::test]
async fn a_watch_type_needs_its_plugin() {
    let types = r#"      - name: orders.created
        source:
          watch:
            strategy: { type: nats_topic, subject: orders }"#;
    let error = build(types, &[]).await.unwrap_err().to_string();
    assert!(error.contains("no loaded watch plugin"), "{error}");
    assert!(error.contains("orders.created"), "{error}");

    let catalog = build(types, &[ScriptedWatch::new("nats_topic")])
        .await
        .unwrap();
    let ty = catalog.get("orders.created").unwrap();
    match &ty.source {
        SourceSpec::Watch {
            kind,
            spec,
            payload,
            ..
        } => {
            assert_eq!(kind, "nats_topic");
            assert_eq!(spec, &json!({"subject": "orders"}));
            assert!(
                payload.is_none(),
                "a watch without event_type carries no payload"
            );
        }
        other => panic!("expected a watch source, got {other:?}"),
    }
    assert!(ty.source.needs_runner());
}

const PAYLOAD_WATCH: &str = r#"      - name: orders.created
        source:
          watch:
            strategy: { type: nats_topic, subject: orders }
            event_type: nats.message"#;

#[tokio::test]
async fn a_strategy_that_declares_no_types_fails_the_payload_binding_at_boot() {
    let error = build(PAYLOAD_WATCH, &[ScriptedWatch::new("nats_topic")])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("declares no event types"), "{error}");
    assert!(error.contains("rebuild"), "{error}");
}

/// A strategy entry for `nats_topic` placed and resuming as given, that
/// declares `nats.message` with `payload_schema`.
fn nats_strategy(
    placement: mcpg_plugin_protocol::EventPlacement,
    resume: bool,
    payload_schema: Option<serde_json::Value>,
) -> mcpg_plugin_protocol::WatchStrategyDescriptor {
    mcpg_plugin_protocol::WatchStrategyDescriptor {
        kind: "nats_topic".to_owned(),
        placement,
        resume,
        event_types: vec![mcpg_plugin_protocol::EventTypeDescriptor {
            name: "nats.message".to_owned(),
            description: "One message.".to_owned(),
            input_schema: None,
            payload_schema,
        }],
    }
}

#[tokio::test]
async fn a_payload_watch_takes_the_plugins_schema_and_placement() {
    use mcpg_plugin_protocol::EventPlacement;
    let catalog = build(
        PAYLOAD_WATCH,
        &[ScriptedWatch::declaring(nats_strategy(
            EventPlacement::EveryReplica,
            true,
            Some(json!({ "type": "object", "required": ["subject"] })),
        ))],
    )
    .await
    .unwrap();
    let ty = catalog.get("orders.created").unwrap();
    assert_eq!(
        ty.payload_schema,
        json!({ "type": "object", "required": ["subject"] })
    );
    assert!(ty.source.runs_on_every_replica());
    assert!(ty.source.resumes());
    assert!(!ty.source.needs_runner());

    let unknown = build(
        &PAYLOAD_WATCH.replace("nats.message", "nats.other"),
        &[ScriptedWatch::declaring(nats_strategy(
            EventPlacement::SingleOwner,
            false,
            None,
        ))],
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unknown.contains("nats.message"),
        "names what it declares: {unknown}"
    );
}

/// Placement belongs to the strategy: a payload-free source of a strategy
/// that runs on every replica runs there too, or the deliveries its
/// upstream sends to the other replicas are lost.
#[tokio::test]
async fn a_payload_free_watch_runs_where_its_strategy_runs() {
    use mcpg_plugin_protocol::EventPlacement;
    let payload_free = r#"      - name: orders.changed
        source:
          watch:
            strategy: { type: nats_topic, subject: orders }"#;
    let catalog = build(
        payload_free,
        &[ScriptedWatch::declaring(nats_strategy(
            EventPlacement::EveryReplica,
            false,
            None,
        ))],
    )
    .await
    .unwrap();
    let ty = catalog.get("orders.changed").unwrap();
    assert!(ty.source.runs_on_every_replica());
    assert!(
        !ty.source.resumes(),
        "only a payload source keeps positions"
    );

    let plain = build(payload_free, &[ScriptedWatch::new("nats_topic")])
        .await
        .unwrap();
    assert!(
        !plain
            .get("orders.changed")
            .unwrap()
            .source
            .runs_on_every_replica(),
        "a strategy its plugin declares nothing for runs on the owner"
    );
}

#[tokio::test]
async fn a_resource_type_takes_the_bindings_strategy() {
    let catalog = build(
        r#"      - name: report.changed
        source:
          resource: file:///data/report.csv"#,
        &[],
    )
    .await
    .unwrap();
    match &catalog.get("report.changed").unwrap().source {
        SourceSpec::Resource { uri, strategy } => {
            assert_eq!(uri, "file:///data/report.csv");
            assert_eq!(
                strategy,
                &ResourceStrategy::Poll {
                    interval_ms: 15_000
                }
            );
        }
        other => panic!("expected a resource source, got {other:?}"),
    }
}

#[tokio::test]
async fn a_transform_needs_a_loaded_plugin() {
    let error = build(
        r#"      - name: gh.issue
        transform: { plugin: dev.mcpg.transform.jsonata, expression: '{"n": number}' }
        source: { inbound: { source_id: gh, allow_unsigned: true } }"#,
        &[],
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not a loaded transform plugin"), "{error}");
}

#[tokio::test]
async fn schemas_validate_arguments_and_payloads() {
    let catalog = build(
        r#"      - name: orders
        input_schema: { type: object, properties: { region: { type: string } }, additionalProperties: false }
        payload_schema: { type: object, required: [orderId] }
        source: { inbound: { source_id: o, allow_unsigned: true } }"#,
        &[],
    )
    .await
    .unwrap();
    let ty = catalog.get("orders").unwrap();
    let args = |v: serde_json::Value| v.as_object().cloned().unwrap();
    assert!(ty.arguments_are_valid(&args(json!({"region": "eu"}))));
    assert!(ty.arguments_are_valid(&args(json!({}))));
    assert!(!ty.arguments_are_valid(&args(json!({"region": 1}))));
    assert!(!ty.arguments_are_valid(&args(json!({"other": "x"}))));
    assert!(ty.payload_is_valid(&json!({"orderId": "o-1"})));
    assert!(!ty.payload_is_valid(&json!({})));
    assert!(ty.offers(DeliveryMode::Webhook));
    assert!(!ty.offers(DeliveryMode::Poll));

    let no_arguments = build(INBOUND, &[]).await.unwrap();
    let ty = no_arguments.get("gh.issue").unwrap();
    assert!(ty.arguments_are_valid(&serde_json::Map::new()));
    assert!(!ty.arguments_are_valid(&args(json!({"any": 1}))));
}

fn occurrence(data: serde_json::Value) -> StoredOccurrence {
    StoredOccurrence {
        event_id: "e-1".to_owned(),
        timestamp: "2026-10-03T12:00:00.000Z".to_owned(),
        data,
        audience: None,
        arguments: None,
    }
}

fn verified(attributes: &[(&str, &str)]) -> RequestIdentity {
    RequestIdentity::Verified {
        subject_id: "alice".to_owned(),
        issuer: "https://idp.example".to_owned(),
        auth_provider: "oidc".to_owned(),
        source: "test".to_owned(),
        roles: vec!["sales".to_owned()],
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: attributes
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

#[tokio::test]
async fn match_selects_per_subscription_and_fails_closed() {
    let catalog = build(
        r#"      - name: by.region
        input_schema: { type: object, properties: { region: { type: string } } }
        match: 'size(arguments) == 0 || event.data.region == arguments.region'
        source: { inbound: { source_id: r, allow_unsigned: true } }
      - name: by.subscriber
        match: 'event.data.tenant == subscriber.attributes.tenant && "sales" in subscriber.roles'
        source: { inbound: { source_id: s, allow_unsigned: true } }
      - name: broken
        match: 'event.data.missing.deeper == 1'
        source: { inbound: { source_id: b, allow_unsigned: true } }
      - name: not.bool
        match: '"yes"'
        source: { inbound: { source_id: n, allow_unsigned: true } }
      - name: everything
        source: { inbound: { source_id: e, allow_unsigned: true } }"#,
        &[],
    )
    .await
    .unwrap();
    let args = |v: serde_json::Value| v.as_object().cloned().unwrap();
    let anyone = RequestIdentity::Anonymous {
        source: "t".to_owned(),
    };

    let by_region = catalog.get("by.region").unwrap();
    let eu = occurrence(json!({"region": "eu"}));
    assert!(by_region.matches(&args(json!({"region": "eu"})), &eu, &anyone));
    assert!(!by_region.matches(&args(json!({"region": "us"})), &eu, &anyone));
    assert!(by_region.matches(&serde_json::Map::new(), &eu, &anyone));

    let by_subscriber = catalog.get("by.subscriber").unwrap();
    let acme = occurrence(json!({"tenant": "acme"}));
    let empty = serde_json::Map::new();
    assert!(by_subscriber.matches(&empty, &acme, &verified(&[("tenant", "acme")])));
    assert!(!by_subscriber.matches(&empty, &acme, &verified(&[("tenant", "other")])));
    assert!(!by_subscriber.matches(&empty, &acme, &anyone));

    let broken = catalog.get("broken").unwrap();
    assert!(!broken.matches(&empty, &acme, &anyone));
    let not_bool = catalog.get("not.bool").unwrap();
    assert!(!not_bool.matches(&empty, &acme, &anyone));
    assert!(
        catalog
            .get("everything")
            .unwrap()
            .matches(&empty, &acme, &anyone)
    );
}

#[tokio::test]
async fn fingerprints_track_the_descriptor_and_the_source_separately() {
    let base = build(INBOUND, &[]).await.unwrap();
    let described = build(&INBOUND.replace("An issue was opened.", "Opened."), &[])
        .await
        .unwrap();
    let rerouted = build(&INBOUND.replace("source_id: gh", "source_id: gh2"), &[])
        .await
        .unwrap();
    let ty = |c: &EventCatalog| Arc::clone(c.get("gh.issue").unwrap());
    assert_ne!(
        ty(&base).descriptor_fingerprint,
        ty(&described).descriptor_fingerprint
    );
    assert_eq!(
        ty(&base).source_fingerprint,
        ty(&described).source_fingerprint
    );
    assert_eq!(
        ty(&base).descriptor_fingerprint,
        ty(&rerouted).descriptor_fingerprint
    );
    assert_ne!(
        ty(&base).source_fingerprint,
        ty(&rerouted).source_fingerprint
    );
    assert_eq!(
        ty(&base).descriptor_fingerprint,
        ty(&build(INBOUND, &[]).await.unwrap()).descriptor_fingerprint
    );
}

#[tokio::test]
async fn inbound_secrets_resolve_from_the_secrets_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("GH_HOOK"), "from-the-file").unwrap();
    let yaml = format!(
        r#"
gateway:
  secrets: {{ dir: "{}" }}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    events:
      - name: gh.issue
        source:
          inbound:
            source_id: gh
            verify: {{ profile: github, secrets: ["${{secret.GH_HOOK}}"] }}
"#,
        dir.path().display()
    );
    let config = AppConfig::load_from_yaml_str(&yaml).unwrap();
    let catalog = EventCatalog::build(&config, &keys(), &ScriptedWatch::registry(&[]))
        .await
        .unwrap();
    let SourceSpec::Inbound(spec) = &catalog.get("gh.issue").unwrap().source else {
        panic!("inbound");
    };
    let body = b"{}";
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-hub-signature-256",
        axum::http::HeaderValue::from_str(&format!(
            "sha256={}",
            hex::encode(hmac_sha256::HMAC::mac(body, b"from-the-file"))
        ))
        .unwrap(),
    );
    assert!(spec.verifier.verify(&headers, body, 0).is_ok());

    std::fs::remove_file(dir.path().join("GH_HOOK")).unwrap();
    let error = EventCatalog::build(&config, &keys(), &ScriptedWatch::registry(&[]))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("did not resolve"), "{error}");
    assert!(!error.contains("from-the-file"));
}

#[tokio::test]
async fn watch_specs_reach_the_plugin_resolved_and_a_new_secret_restarts_them() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("DB_PASS"), "first").unwrap();
    let yaml = format!(
        r#"
gateway:
  secrets: {{ dir: "{}" }}
mcp:
  configurations:
    sessions: {{ synthetic_session_key: "{SESSION_KEY}" }}
    events: {{ enabled: true, store: {{ kind: file, dir: /x }} }}
  capabilities:
    resources:
      - name: orders
        description: Orders.
        uri: "db://orders"
        backend: {{ kind: mock, response: "x" }}
        watch: {{ strategy: {{ type: plugin, kind: scripted, url: "db://app:${{secret.DB_PASS}}@db" }} }}
    events:
      - name: orders.watched
        source:
          watch:
            strategy: {{ type: plugin, kind: scripted, url: "db://app:${{secret.DB_PASS}}@db", channel: orders }}
      - name: orders.resource
        source: {{ resource: "db://orders" }}
"#,
        dir.path().display()
    );
    let config = AppConfig::load_from_yaml_str(&yaml).unwrap();
    let registry = ScriptedWatch::registry(&[ScriptedWatch::new("scripted")]);
    let catalog = EventCatalog::build(&config, &keys(), &registry)
        .await
        .unwrap();
    let watched = catalog.get("orders.watched").unwrap();
    let SourceSpec::Watch { spec, .. } = &watched.source else {
        panic!("a watch source");
    };
    assert_eq!(spec["url"], "db://app:first@db");
    assert_eq!(spec["channel"], "orders");
    let SourceSpec::Resource {
        strategy: ResourceStrategy::Plugin { spec, .. },
        ..
    } = &catalog.get("orders.resource").unwrap().source
    else {
        panic!("a resource source over a plugin watch");
    };
    assert_eq!(spec["url"], "db://app:first@db");

    std::fs::write(dir.path().join("DB_PASS"), "second").unwrap();
    let rotated = EventCatalog::build(&config, &keys(), &registry)
        .await
        .unwrap();
    for name in ["orders.watched", "orders.resource"] {
        assert_ne!(
            rotated.get(name).unwrap().source_fingerprint,
            catalog.get(name).unwrap().source_fingerprint,
            "{name}: a rotated secret restarts the source"
        );
        assert_eq!(
            rotated.get(name).unwrap().descriptor_fingerprint,
            catalog.get(name).unwrap().descriptor_fingerprint
        );
    }

    std::fs::remove_file(dir.path().join("DB_PASS")).unwrap();
    let error = format!(
        "{:#}",
        EventCatalog::build(&config, &keys(), &registry)
            .await
            .unwrap_err()
    );
    assert!(error.contains("DB_PASS"), "{error}");
    assert!(!error.contains("second"), "{error}");
}

#[tokio::test]
async fn modes_are_intersected_with_the_enabled_ones() {
    let catalog = build(
        r#"      - name: a
        delivery: [poll, webhook]
        source: { inbound: { source_id: a, allow_unsigned: true } }"#,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        catalog.get("a").unwrap().delivery,
        vec![DeliveryMode::Webhook]
    );
}

fn imported(
    name: &str,
    offered: &[&str],
    delivery: crate::config::federation::UpstreamEventDelivery,
) -> FederatedEventType {
    FederatedEventType {
        federation: "up".to_owned(),
        name: name.to_owned(),
        upstream_name: name.trim_start_matches("up.").to_owned(),
        descriptor: serde_json::from_value(json!({ "name": name, "delivery": offered })).unwrap(),
        delivery,
        sharing: crate::config::federation::UpstreamEventSharing::FanIn,
        retention: Default::default(),
    }
}

fn upstream_mode(ty: &EventType) -> UpstreamMode {
    match &ty.source {
        SourceSpec::Federation { mode, .. } => *mode,
        other => panic!("not a federated source: {}", other.kind()),
    }
}

#[tokio::test]
async fn an_imported_type_is_served_beside_the_configured_ones() {
    use crate::config::events::EventDeliveryMode as Enabled;
    use crate::config::federation::UpstreamEventDelivery as Upstream;
    let configured = build(INBOUND, &[]).await.unwrap();
    let all = [Enabled::Poll, Enabled::Push, Enabled::Webhook];
    let keys = keys();
    let ctx = ImportContext {
        enabled: &all,
        keys: &keys,
        callbacks: false,
    };
    let compiled = configured.compile_federated(
        &[
            imported("up.both", &["poll", "push"], Upstream::Auto),
            imported("up.polled", &["poll", "push"], Upstream::Poll),
            imported("up.poll_only", &["poll"], Upstream::Auto),
            imported("up.push_only", &["push"], Upstream::Poll),
            imported("gh.issue", &["poll"], Upstream::Auto),
            imported("up.both", &["poll"], Upstream::Auto),
        ],
        &ctx,
    );
    let names: Vec<&str> = compiled.iter().map(|ty| ty.name.as_str()).collect();
    assert_eq!(
        names,
        ["up.both", "up.polled", "up.poll_only"],
        "a type the upstream cannot be read for, or whose name is taken, is left out"
    );
    assert_eq!(
        upstream_mode(&compiled[0]),
        UpstreamMode::Push,
        "auto prefers push"
    );
    assert_eq!(upstream_mode(&compiled[1]), UpstreamMode::Poll);
    assert_eq!(upstream_mode(&compiled[2]), UpstreamMode::Poll);
    assert!(
        compiled.iter().all(|ty| ty.delivery
            == [
                DeliveryMode::Poll,
                DeliveryMode::Push,
                DeliveryMode::Webhook
            ]
            && ty.replay == EventReplay::Log),
        "served from the gateway's own log, in every enabled mode"
    );

    let merged = configured.with_types(compiled);
    assert_eq!(merged.len(), 4);
    assert!(merged.get("up.both").is_some() && merged.get("gh.issue").is_some());
    assert_eq!(
        merged.by_source_id("gh").len(),
        1,
        "the configured inbound route stays"
    );
    let back = merged.configured();
    assert_eq!(back.len(), 1);
    assert!(back.get("gh.issue").is_some());
}

/// Imported types take their retention from what the event-log store has
/// left after the configured types; one that does not fit is not served.
#[tokio::test]
async fn imported_types_share_what_the_log_store_has_left() {
    use crate::config::events::EventDeliveryMode as Enabled;
    use crate::config::federation::UpstreamEventDelivery as Upstream;
    // A single node's memory store holds 64 MiB; the configured type keeps 8.
    let configured = build(INBOUND, &[]).await.unwrap();
    let keys = keys();
    let ctx = ImportContext {
        enabled: &[Enabled::Poll],
        keys: &keys,
        callbacks: false,
    };
    let many: Vec<FederatedEventType> = (0..8)
        .map(|i| imported(&format!("up.t{i}"), &["poll"], Upstream::Auto))
        .collect();
    assert_eq!(
        configured.compile_federated(&many, &ctx).len(),
        7,
        "seven 8 MiB budgets fit the 56 MiB left"
    );
    let small: Vec<FederatedEventType> = many
        .into_iter()
        .map(|mut ty| {
            ty.retention.max_bytes = Some(1024 * 1024);
            ty
        })
        .collect();
    let compiled = configured.compile_federated(&small, &ctx);
    assert_eq!(compiled.len(), 8);
    assert_eq!(compiled[0].retention.max_bytes, Some(1024 * 1024));
}

#[test]
fn webhook_upstream_delivery_needs_a_public_address() {
    use crate::config::events::EventDeliveryMode as Enabled;
    use crate::config::federation::UpstreamEventDelivery as Upstream;
    let keys = keys();
    let types = [
        imported("up.auto", &["poll", "push", "webhook"], Upstream::Auto),
        imported("up.hooked", &["poll", "webhook"], Upstream::Webhook),
    ];
    let compile = |callbacks: bool| {
        EventCatalog::empty().compile_federated(
            &types,
            &ImportContext {
                enabled: &[Enabled::Poll],
                keys: &keys,
                callbacks,
            },
        )
    };
    let public = compile(true);
    assert_eq!(
        upstream_mode(&public[0]),
        UpstreamMode::Webhook,
        "auto prefers webhook"
    );
    assert_eq!(upstream_mode(&public[1]), UpstreamMode::Webhook);
    let private = compile(false);
    assert_eq!(
        private.len(),
        1,
        "webhook alone cannot be read without a public address"
    );
    assert_eq!(upstream_mode(&private[0]), UpstreamMode::Push);
}
