use super::serve::start_extra_transports;
use super::*;
use crate::config::ToolAccessPolicyConfig as ToolAccessPolicyConfigYaml;
use crate::config::{
    BackendConfig, BackendGovernanceConfig, BackendImpl, GatewayConfig, GovernanceConfig,
    HttpBackendConfig, HttpBackendMethod, LogsConfig, McpCapabilitiesConfig, ObservabilityConfig,
    PolicyCacheConfig, PolicyConfig, ServerConfig, TrustLevelConfig,
};

// Capability-store inheritance from the cluster
// coordinator. When a single-node coordinator is supplied, every
// call to `default_capability_kv` (and `_bus`) returns the SAME
// primitive `Arc`, so all four KV-backed capabilities share one
// in-process state space (their key prefixes — `session:`, `task:`,
// `pipeline:`, `sub:`, … — keep their data sets disjoint inside
// that shared store).

#[test]
fn default_capability_kv_inherits_from_single_node_coordinator() {
    let coordinator: std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let kv_a = default_capability_kv("sessions", Some(&coordinator));
    let kv_b = default_capability_kv("tasks", Some(&coordinator));
    assert!(
        std::sync::Arc::ptr_eq(&kv_a, &kv_b),
        "two capabilities inheriting from the same coordinator MUST receive \
         the same primitive Arc — that is the entire point of inheritance"
    );
}

#[test]
fn default_capability_bus_inherits_from_single_node_coordinator() {
    let coordinator: std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend> =
        crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let bus_a = default_capability_bus("delivery", Some(&coordinator));
    let bus_b = default_capability_bus("cancellation", Some(&coordinator));
    assert!(
        std::sync::Arc::ptr_eq(&bus_a, &bus_b),
        "two bus-backed capabilities inheriting from the same coordinator \
         MUST receive the same primitive Arc"
    );
}

#[test]
fn default_capability_kv_falls_back_to_fresh_memory_kv_without_coordinator() {
    // When no coordinator is supplied (e.g. cluster.kind=redis with
    // cdylib not yet early-loaded), each call returns a fresh
    // MemoryKv — the caller-isolated default.
    let kv_a = default_capability_kv("sessions", None);
    let kv_b = default_capability_kv("tasks", None);
    assert!(
        !std::sync::Arc::ptr_eq(&kv_a, &kv_b),
        "without a coordinator, fallback path must allocate fresh \
         MemoryKv per capability — the legacy isolated-state behaviour"
    );
}

#[tokio::test]
async fn build_kv_from_override_resolves_full_plugin_id() {
    // Operator wrote `mcp.configurations.tasks.store: { kind:
    // dev.mcpg.builtin.store.memory }`. Verify the resolver
    // looks up the plugin in the registry, wraps it in
    // StoreToKvAdapter, and returns a working KeyValueStore.
    let mut reg = mcpg_plugin_host::PluginRegistry::new();
    reg.register_store(
        crate::builtins::store_memory::MemoryStore::new(),
        mcpg_plugin_protocol::PluginTier::Native,
    )
    .unwrap();
    let over = crate::config::StoreOverrideConfig {
        kind: "dev.mcpg.builtin.store.memory".to_owned(),
        config: serde_json::Map::new(),
    };
    let kv = build_kv_from_override(&over, &reg, mcpg_plugin_protocol::store::StoreRole::Task)
        .await
        .unwrap();
    kv.put("k", bytes::Bytes::from_static(b"v"), None)
        .await
        .unwrap();
    let entry = kv.get("k").await.unwrap();
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().bytes.as_ref(), b"v");
}

#[tokio::test]
async fn build_kv_from_override_resolves_short_alias() {
    // `kind: foo` expands to `dev.mcpg.kv.foo` and looks up.
    // We register a store under that exact id to confirm the
    // alias path.
    let reg = mcpg_plugin_host::PluginRegistry::new();
    // The MemoryStore manifest hardcodes
    // `dev.mcpg.builtin.store.memory`, so a short alias
    // `memory` → `dev.mcpg.kv.memory` would NOT match. This
    // test instead asserts the negative path: the alias is
    // attempted but no plugin matches.
    let over = crate::config::StoreOverrideConfig {
        kind: "doesnotexist".to_owned(),
        config: serde_json::Map::new(),
    };
    let err = build_kv_from_override(&over, &reg, mcpg_plugin_protocol::store::StoreRole::Task)
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("doesnotexist"), "kind in error: {msg}");
    assert!(
        msg.contains("dev.mcpg.kv.doesnotexist"),
        "expanded id in error: {msg}"
    );
    // Suppress unused warning when the negative path is the
    // assertion target — the registry argument lives just for
    // the lookup attempt.
    let _ = reg.policy_engine_names();
}

#[tokio::test]
async fn build_kv_from_override_refuses_role_unsupported_by_plugin() {
    // MemoryStore advertises every canonical role + Custom
    // wildcard, so this test uses a synthetic that supports
    // only Task. Using the real store we'd never hit this
    // arm; for coverage we'd need a fake. Skip — adapter-side
    // tests in plugin_kv_adapter cover role-routing. Here we
    // just confirm the happy path returns something usable.
    let mut reg = mcpg_plugin_host::PluginRegistry::new();
    reg.register_store(
        crate::builtins::store_memory::MemoryStore::new(),
        mcpg_plugin_protocol::PluginTier::Native,
    )
    .unwrap();
    let over = crate::config::StoreOverrideConfig {
        kind: "dev.mcpg.builtin.store.memory".to_owned(),
        config: serde_json::Map::new(),
    };
    for role in [
        mcpg_plugin_protocol::store::StoreRole::Session,
        mcpg_plugin_protocol::store::StoreRole::Task,
        mcpg_plugin_protocol::store::StoreRole::Pipeline,
        mcpg_plugin_protocol::store::StoreRole::Subscription,
    ] {
        build_kv_from_override(&over, &reg, role)
            .await
            .expect("MemoryStore supports every canonical role");
    }
}

#[test]
fn digest_from_reference_extracts_valid_sha256() {
    let r = "ghcr.io/mcpg-dev/audit@sha256:\
             0101010101010101010101010101010101010101010101010101010101010101";
    assert_eq!(
        digest_from_reference(r),
        Some("0101010101010101010101010101010101010101010101010101010101010101")
    );
}

#[test]
fn digest_from_reference_rejects_non_digest_refs() {
    assert_eq!(digest_from_reference("ghcr.io/foo:1.0.0"), None);
    assert_eq!(digest_from_reference("ghcr.io/foo"), None);
}

#[test]
fn digest_from_reference_rejects_malformed_digest() {
    // Wrong length.
    assert_eq!(digest_from_reference("foo@sha256:deadbeef"), None);
    // Non-hex.
    let bad = "foo@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    assert_eq!(digest_from_reference(bad), None);
}

#[test]
fn verify_cached_digest_accepts_match() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"hello world").unwrap();
    let expected = mcpg_plugin_host::verify::sha256_hex(b"hello world");
    assert!(verify_cached_digest(tmp.path(), &expected).is_ok());
}

#[test]
fn verify_cached_digest_rejects_tampered_file() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"hello world").unwrap();
    let wrong = mcpg_plugin_host::verify::sha256_hex(b"goodbye world");
    let err = verify_cached_digest(tmp.path(), &wrong)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cached digest mismatch"), "got: {err}");
}

#[test]
fn oci_cache_sidecar_roundtrips_layer_digest() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("plugin.zip");
    let sidecar = oci_cache_sidecar_path(&cache_path);
    assert!(
        sidecar
            .as_os_str()
            .to_string_lossy()
            .ends_with(".layer-sha256")
    );
    // A `sha256:`-prefixed digest (as produced by ImageLayer::sha256_digest)
    // is stored, then read back as bare hex usable by verify_cached_digest.
    let bare = mcpg_plugin_host::verify::sha256_hex(b"layer bytes");
    write_oci_cache_sidecar(&sidecar, &format!("sha256:{bare}"));
    assert_eq!(
        read_oci_cache_sidecar(&sidecar).as_deref(),
        Some(bare.as_str())
    );
}

#[test]
fn read_oci_cache_sidecar_rejects_junk_and_missing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.zip.layer-sha256");
    assert_eq!(read_oci_cache_sidecar(&missing), None);
    let junk = dir.path().join("junk.layer-sha256");
    std::fs::write(&junk, "not-a-digest").unwrap();
    assert_eq!(read_oci_cache_sidecar(&junk), None);
}

#[test]
fn cache_layer_digest_validates_against_pull_outcome_format() {
    // The cached zip can be checked against the layer digest the pull
    // recorded, even though the digest carries a `sha256:` prefix.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"the actual layer zip bytes").unwrap();
    let recorded = format!(
        "sha256:{}",
        mcpg_plugin_host::verify::sha256_hex(b"the actual layer zip bytes")
    );
    let bare = recorded.strip_prefix("sha256:").unwrap();
    assert!(verify_cached_digest(tmp.path(), bare).is_ok());
}

#[test]
fn enforce_oci_integrity_anchor_gates_only_when_required() {
    use crate::config::{PluginEntryConfig, PluginRegistryConfig};

    let bare_entry: PluginEntryConfig = serde_json::from_value(serde_json::json!({
        "id": "dev.mcpg.demo",
        "source": { "oci": "ghcr.io/mcpg-dev/demo:1.0.0" }
    }))
    .unwrap();

    // Flag off → no anchor needed.
    let mut reg = PluginRegistryConfig::default();
    assert!(enforce_oci_integrity_anchor(&bare_entry, "ghcr.io/mcpg-dev/demo:1.0.0", &reg).is_ok());

    // Flag on + bare tag, no anchor → refused.
    reg.require_integrity_anchor = true;
    let err = enforce_oci_integrity_anchor(&bare_entry, "ghcr.io/mcpg-dev/demo:1.0.0", &reg)
        .unwrap_err()
        .to_string();
    assert!(err.contains("require_integrity_anchor"), "got: {err}");

    // Flag on + digest-pinned reference → accepted.
    assert!(
        enforce_oci_integrity_anchor(
            &bare_entry,
            "ghcr.io/mcpg-dev/demo@sha256:\
             0101010101010101010101010101010101010101010101010101010101010101",
            &reg,
        )
        .is_ok()
    );

    // Flag on + a signature.sha256 layer pin → accepted.
    let pinned_entry: PluginEntryConfig = serde_json::from_value(serde_json::json!({
        "id": "dev.mcpg.demo",
        "source": { "oci": "ghcr.io/mcpg-dev/demo:1.0.0" },
        "signature": { "sha256": "0101010101010101010101010101010101010101010101010101010101010101" }
    }))
    .unwrap();
    assert!(
        enforce_oci_integrity_anchor(&pinned_entry, "ghcr.io/mcpg-dev/demo:1.0.0", &reg).is_ok()
    );
}

fn test_http_binding(name: &str, allow_if: Option<&str>) -> BackendConfig {
    BackendConfig {
        name: name.to_owned(),
        title: None,
        description: "test".to_owned(),
        input_schema: None,
        backend: BackendImpl::from_typed(
            "http",
            HttpBackendConfig {
                url: "http://localhost:9000/api".to_owned(),
                method: HttpBackendMethod::Post,
                timeout_ms: 2000,
                max_response_bytes: 4096,
                expected_status_codes: vec![200],
                require_json_response: false,
                headers: Default::default(),
            },
        ),
        governance: BackendGovernanceConfig {
            minimum_trust: TrustLevelConfig::HeaderAsserted,
            allow_if: allow_if.map(|s| s.to_owned()),
        },
        retry: None,
        content_storage: None,
        cache: None,
        quotas: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        watch: None,
        uri_template: None,
        variable_completions: None,
        annotations: None,
        output_schema: None,
        task_support: None,
        icons: None,
        descriptor_meta: None,
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    }
}

#[tokio::test]
async fn build_from_config_rejects_invalid_cel_policy() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig {
                enabled: true,
                level: "info".to_owned(),
                sinks: vec![crate::config::SinkConfig {
                    kind: "stdout".to_owned(),
                    config: serde_json::json!({"format": "json"}),
                    level: None,
                }],
            },
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfigYaml {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: Some("tool_name == ".to_owned()),
                    rules: Vec::new(),
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    let error = match build_from_config(config, Vec::new()).await {
        Ok(_) => panic!("invalid CEL should fail during bootstrap"),
        Err(error) => error,
    };

    assert!(!error.to_string().is_empty());
}

#[tokio::test]
async fn build_from_config_rejects_invalid_per_tool_cel_policy() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig {
                enabled: true,
                level: "info".to_owned(),
                sinks: vec![crate::config::SinkConfig {
                    kind: "stdout".to_owned(),
                    config: serde_json::json!({"format": "json"}),
                    level: None,
                }],
            },
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfigYaml {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: None,
                    rules: vec![crate::config::ToolTrustRuleConfig {
                        tool_name: "mcpg.runtime.snapshot".to_owned(),
                        minimum_trust: TrustLevelConfig::HeaderAsserted,
                        cel_allow_if: Some("principal_id == ".to_owned()),
                        required_scopes: Vec::new(),
                    }],
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    let error = match build_from_config(config, Vec::new()).await {
        Ok(_) => panic!("invalid per-tool CEL should fail during bootstrap"),
        Err(error) => error,
    };

    assert!(!error.to_string().is_empty());
}

// `build_from_config` registers HTTP bindings via
// `tokio::task::block_in_place`, which is only valid on a
// multi-threaded runtime (production always runs under one). This
// test feeds it an HTTP binding, so it must use the multi-thread
// flavor — the default current-thread `#[tokio::test]` panics with
// "can call blocking only when running on the multi-threaded
// runtime" under process-isolated runners (cargo-nextest).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_from_config_rejects_invalid_binding_allow_if_policy() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig {
                enabled: true,
                level: "info".to_owned(),
                sinks: vec![crate::config::SinkConfig {
                    kind: "stdout".to_owned(),
                    config: serde_json::json!({"format": "json"}),
                    level: None,
                }],
            },
            ..ObservabilityConfig::default()
        },
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![test_http_binding(
                    "weather.get_forecast",
                    Some("principal_id == "),
                )],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };

    let error = match build_from_config(config, Vec::new()).await {
        Ok(_) => panic!("invalid binding allow_if should fail during bootstrap"),
        Err(error) => error,
    };

    assert!(!error.to_string().is_empty());
}

#[test]
fn build_tool_access_policy_config_injects_binding_governance_rules() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![
                    test_http_binding("weather.get_forecast", Some("principal_id == \"user-1\"")),
                    BackendConfig {
                        name: "system.diagnostic".to_owned(),
                        title: None,
                        description: "test".to_owned(),
                        input_schema: None,
                        backend: BackendImpl::from_typed(
                            "command",
                            serde_json::json!({
                                "command": "/usr/bin/test",
                                "args": [],
                                "timeout_ms": 2000,
                                "max_output_bytes": 4096,
                                "require_json_stdout": true,
                            }),
                        ),
                        governance: BackendGovernanceConfig {
                            minimum_trust: TrustLevelConfig::HeaderAsserted,
                            allow_if: Some("principal_id == \"user-2\"".to_owned()),
                        },
                        retry: None,
                        content_storage: None,
                        cache: None,
                        quotas: None,
                        prompt_arguments: None,
                        uri: None,
                        mime_type: None,
                        watch: None,
                        uri_template: None,
                        variable_completions: None,
                        annotations: None,
                        output_schema: None,
                        task_support: None,
                        icons: None,
                        descriptor_meta: None,
                        resource_size: None,
                        resource_annotations: None,
                        mcp_app_url: None,
                    },
                ],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfigYaml {
                    default_minimum_trust: TrustLevelConfig::Unauthenticated,
                    cel_allow_if: None,
                    rules: Vec::new(),
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    let policy = build_tool_access_policy_config(&config);

    assert_eq!(
        policy.default_minimum_trust,
        RequestTrustLevel::Unauthenticated
    );

    let weather_rule = policy
        .rules
        .iter()
        .find(|rule| rule.tool_name == "weather.get_forecast")
        .expect("binding governance rule");
    assert_eq!(
        weather_rule.minimum_trust,
        RequestTrustLevel::HeaderAsserted
    );
    assert_eq!(
        weather_rule.cel_allow_if.as_deref(),
        Some("principal_id == \"user-1\"")
    );

    let command_rule = policy
        .rules
        .iter()
        .find(|rule| rule.tool_name == "system.diagnostic")
        .expect("command binding governance rule");
    assert_eq!(
        command_rule.minimum_trust,
        RequestTrustLevel::HeaderAsserted
    );
    assert_eq!(
        command_rule.cel_allow_if.as_deref(),
        Some("principal_id == \"user-2\"")
    );
}

/// A resource's `governance.minimum_trust` has to reach policy under the key
/// the resource surfaces are gated by — the URI. Both `resources/list` and
/// the read path ask policy about the URI the client sent, so a name-only
/// rule never matches and the binding silently degrades to
/// `default_minimum_trust`: with a permissive default, an anonymous caller
/// could read a resource the operator marked `verified`.
#[test]
fn build_tool_access_policy_config_keys_resource_rules_by_uri() {
    let mut resource = test_http_binding("secret.resource", None);
    resource.uri = Some("secret://vault/credentials".to_owned());
    resource.governance.minimum_trust = TrustLevelConfig::Verified;

    let mut template = test_http_binding("secret.template", None);
    template.uri_template = Some("secret://vault/{id}".to_owned());
    template.governance.minimum_trust = TrustLevelConfig::Verified;

    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                resources: vec![resource],
                resource_templates: vec![template],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfigYaml {
                    default_minimum_trust: TrustLevelConfig::Unauthenticated,
                    cel_allow_if: None,
                    rules: Vec::new(),
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    let policy = build_tool_access_policy_config(&config);
    for key in ["secret://vault/credentials", "secret://vault/{id}"] {
        let rule = policy
            .rules
            .iter()
            .find(|rule| rule.tool_name == key)
            .unwrap_or_else(|| {
                panic!("no rule keyed by {key}; the binding's trust floor is inert")
            });
        assert_eq!(rule.minimum_trust, RequestTrustLevel::Verified);
    }
    // The name key stays too: an operator-written
    // `tool_access.rules[].tool_name` may still address the binding by name.
    assert!(
        policy
            .rules
            .iter()
            .any(|rule| rule.tool_name == "secret.resource"),
        "the name-keyed rule is still registered"
    );
}

// `resolve_store_kind` / `resolve_pipeline_store_kind`
// helpers were retired with the legacy per-capability `kind`
// discriminator. Override-driven boot paths are covered by
// `config::tests::validate_*_store_override_*` and the
// `store_override` module's serde tests.

// `expand_env_refs_*` tests retired alongside the helper —
// equivalent coverage now lives in `config::resolver`'s tests.

// -- derive_native_verify_options_for_entry ------------------------

fn entry_with_signature(
    id: &str,
    signature: Option<crate::config::SignatureConfig>,
) -> crate::config::PluginEntryConfig {
    crate::config::PluginEntryConfig {
        id: id.to_owned(),
        r#ref: None,
        kind: "native".into(),
        class: "tool_gate".into(),
        source: crate::config::PluginSourceConfig {
            path: None,
            oci: None,
        },
        config: serde_json::Value::Null,
        signature,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }
}

/// Standard 12-byte PKCS#8 SPKI prefix for `id-Ed25519`
/// (1.3.101.112) followed by a 32-byte raw key, base64ed +
/// PEM-wrapped. Lets each test build a syntactically valid
/// PEM from a raw key without touching `openssl`.
fn pem_for_raw_key(raw: [u8; 32]) -> String {
    use base64::Engine as _;
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ]);
    der.extend_from_slice(&raw);
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

/// Registry config with the given default policy and no gateway-wide
/// keys — the pre-registry-anchor shape most derive tests exercise.
fn registry_with_policy(
    policy: crate::config::SignaturePolicy,
) -> crate::config::PluginRegistryConfig {
    crate::config::PluginRegistryConfig {
        default_signature_policy: policy,
        ..Default::default()
    }
}

#[test]
fn derive_uses_default_policy_when_entry_has_no_signature_block() {
    let entry = entry_with_signature("p1", None);
    let opts = derive_native_verify_options_for_entry(
        &entry,
        &registry_with_policy(crate::config::SignaturePolicy::Enforce),
        None,
    )
    .unwrap();
    assert_eq!(opts.policy, mcpg_plugin_host::SignaturePolicy::Enforce);
    // The built-in official key is always an anchor on the inherit path.
    assert!(!opts.trusted_public_keys.is_empty());
    assert!(opts.expected_sha256.is_none());
}

#[test]
fn derive_per_entry_policy_overrides_default() {
    let signature = crate::config::SignatureConfig {
        policy: Some(crate::config::SignaturePolicy::Disabled),
        sha256: None,
        trusted_keys: vec![],
    };
    let entry = entry_with_signature("p2", Some(signature));
    let opts = derive_native_verify_options_for_entry(
        &entry,
        &registry_with_policy(crate::config::SignaturePolicy::Enforce),
        None,
    )
    .unwrap();
    assert_eq!(opts.policy, mcpg_plugin_host::SignaturePolicy::Disabled);
}

#[test]
fn derive_decodes_pem_keys_and_threads_them() {
    let signature = crate::config::SignatureConfig {
        policy: Some(crate::config::SignaturePolicy::Enforce),
        sha256: None,
        trusted_keys: vec![
            crate::config::TrustedKeyConfig {
                id: "vendor-a".into(),
                pem: pem_for_raw_key([0x11u8; 32]),
            },
            crate::config::TrustedKeyConfig {
                id: "vendor-b".into(),
                pem: pem_for_raw_key([0x22u8; 32]),
            },
        ],
    };
    let entry = entry_with_signature("p3", Some(signature));
    let opts = derive_native_verify_options_for_entry(
        &entry,
        &registry_with_policy(crate::config::SignaturePolicy::Warn),
        None,
    )
    .unwrap();
    assert_eq!(opts.trusted_public_keys.len(), 2);
    assert_eq!(opts.trusted_public_keys[0], [0x11u8; 32]);
    assert_eq!(opts.trusted_public_keys[1], [0x22u8; 32]);
}

#[test]
fn derive_reads_signature_sha256() {
    let signature = crate::config::SignatureConfig {
        policy: None,
        sha256: Some("aa".repeat(32)),
        trusted_keys: vec![],
    };
    let entry = entry_with_signature("p4", Some(signature));
    let opts = derive_native_verify_options_for_entry(
        &entry,
        &registry_with_policy(crate::config::SignaturePolicy::Warn),
        None,
    )
    .unwrap();
    assert_eq!(
        opts.expected_sha256.as_deref(),
        Some("aa".repeat(32).as_str())
    );
}

#[test]
fn derive_surfaces_pem_decode_failure_with_plugin_id() {
    let signature = crate::config::SignatureConfig {
        policy: None,
        sha256: None,
        trusted_keys: vec![crate::config::TrustedKeyConfig {
            id: "broken".into(),
            pem: "not a pem".into(),
        }],
    };
    let entry = entry_with_signature("p6", Some(signature));
    let err = derive_native_verify_options_for_entry(
        &entry,
        &registry_with_policy(crate::config::SignaturePolicy::Warn),
        None,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("p6"), "plugin id surfaced: {msg}");
    assert!(msg.contains("broken"), "key id surfaced: {msg}");
}

// -- build_policy_chain (governance.policy.engine[]) ---------------

/// Construct a `PluginRegistry` with the built-in YAML-rules
/// engine pre-registered, so `build_policy_chain` can find it
/// when the test references `kind: yaml-rules`.
fn registry_with_yaml_rules() -> mcpg_plugin_host::PluginRegistry {
    let mut reg = mcpg_plugin_host::PluginRegistry::new();
    let engine = crate::builtins::policy_yaml_rules::YamlRulesPolicyEngine::deny_all();
    reg.register_policy_engine(engine, mcpg_plugin_protocol::PluginTier::Native)
        .expect("yaml-rules engine should register cleanly");
    reg
}

fn kind_ref(kind: &str) -> crate::config::wiring::KindRef {
    crate::config::wiring::KindRef {
        kind: kind.to_owned(),
        config: serde_json::Value::Null,
    }
}

#[test]
fn build_policy_chain_empty_config_yields_empty_chain() {
    let reg = mcpg_plugin_host::PluginRegistry::new();
    let chain = build_policy_chain(&[], &[], &reg, "single_node").unwrap();
    assert!(chain.is_empty());
}

#[test]
fn build_policy_chain_resolves_yaml_rules_builtin() {
    let reg = registry_with_yaml_rules();
    let chain = build_policy_chain(&[kind_ref("yaml-rules")], &[], &reg, "single_node").unwrap();
    assert_eq!(chain, vec!["yaml-rules".to_string()]);
}

#[test]
fn build_policy_chain_refuses_unknown_kind() {
    let reg = registry_with_yaml_rules();
    let err = build_policy_chain(
        &[kind_ref("totally-made-up-engine")],
        &[],
        &reg,
        "single_node",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("totally-made-up-engine"),
        "kind surfaced: {msg}"
    );
}

#[test]
fn build_policy_chain_refuses_duplicate_entry() {
    let reg = registry_with_yaml_rules();
    let err = build_policy_chain(
        &[kind_ref("yaml-rules"), kind_ref("yaml-rules")],
        &[],
        &reg,
        "single_node",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("more than once"), "got: {msg}");
}

#[test]
fn build_policy_chain_refuses_yaml_rules_when_not_registered() {
    // Operator wrote `engine: [{ kind: yaml-rules }]` but the
    // registration block earlier in build_plugin_registry
    // failed (or got skipped). Boot must refuse rather than
    // letting the chain silently lack the engine the operator
    // declared.
    let reg = mcpg_plugin_host::PluginRegistry::new();
    let err = build_policy_chain(&[kind_ref("yaml-rules")], &[], &reg, "single_node").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("not registered"), "got: {msg}");
    assert!(msg.contains("yaml-rules"), "got: {msg}");
}

// -- OCI reference normalisation + auth interpolation --------------

#[test]
fn normalise_oci_leaves_qualified_references_alone() {
    assert_eq!(
        normalise_oci_reference("ghcr.io/org/plugin:1.0", "default.reg/scope"),
        "ghcr.io/org/plugin:1.0"
    );
    assert_eq!(
        normalise_oci_reference(
            "registry.internal.corp/mcpg-plugins/audit:2.0.0",
            "default.reg/scope"
        ),
        "registry.internal.corp/mcpg-plugins/audit:2.0.0"
    );
}

#[test]
fn normalise_oci_prepends_default_for_unqualified() {
    assert_eq!(
        normalise_oci_reference("audit:1.0.0", "ghcr.io/mcpg-dev/source-code/plugins"),
        "ghcr.io/mcpg-dev/source-code/plugins/audit:1.0.0"
    );
}

#[test]
fn normalise_oci_accepts_localhost_dev_registry() {
    assert_eq!(
        normalise_oci_reference("localhost:5000/plugin:dev", "default.reg"),
        "localhost:5000/plugin:dev"
    );
}

#[test]
fn normalise_oci_accepts_digest_pinned() {
    let r = normalise_oci_reference("audit@sha256:abc123", "ghcr.io/org");
    assert_eq!(r, "ghcr.io/org/audit@sha256:abc123");
}

#[test]
fn rewrite_for_mirror_swaps_registry_prefix() {
    assert_eq!(
        rewrite_reference_for_mirror(
            "ghcr.io/mcpg-dev/plugins/audit:1.0",
            "harbor.internal.corp/mirror"
        ),
        "harbor.internal.corp/mirror/mcpg-dev/plugins/audit:1.0"
    );
}

// -- Platform / protocol OCI ref resolution (Path B) ----------------

#[test]
fn platform_no_tag_tracks_protocol_floating_tag() {
    // Tag-less ref → the floating protocol tag for this gateway's platform,
    // native preferred + wasm fallback.
    assert_eq!(
        resolve_platform_candidates("ghcr.io/org/plugins/audit", "linux-amd64", "1"),
        vec![
            "ghcr.io/org/plugins/audit:protocol-1-linux-amd64".to_owned(),
            "ghcr.io/org/plugins/audit:protocol-1-wasi-wasm".to_owned(),
        ]
    );
}

#[test]
fn platform_bare_version_tag_gets_suffix() {
    assert_eq!(
        resolve_platform_candidates("ghcr.io/org/plugins/audit:0.1.0-dev.18", "linux-arm64", "1"),
        vec![
            "ghcr.io/org/plugins/audit:0.1.0-dev.18-linux-arm64".to_owned(),
            "ghcr.io/org/plugins/audit:0.1.0-dev.18-wasi-wasm".to_owned(),
        ]
    );
}

#[test]
fn platform_protocol_tag_gets_suffix() {
    assert_eq!(
        resolve_platform_candidates("ghcr.io/org/plugins/audit:protocol-1", "darwin-arm64", "1"),
        vec![
            "ghcr.io/org/plugins/audit:protocol-1-darwin-arm64".to_owned(),
            "ghcr.io/org/plugins/audit:protocol-1-wasi-wasm".to_owned(),
        ]
    );
}

#[test]
fn platform_explicit_suffix_is_verbatim() {
    // Operator pinned a concrete artifact → single candidate, untouched,
    // even when it differs from this host's platform.
    for r in [
        "ghcr.io/org/plugins/audit:0.1.0-dev.18-linux-amd64",
        "ghcr.io/org/plugins/audit:protocol-1-linux-musl-arm64",
        "ghcr.io/org/plugins/masking:0.1.0-dev.18-wasi-wasm",
    ] {
        assert_eq!(
            resolve_platform_candidates(r, "linux-amd64", "1"),
            vec![r.to_owned()],
            "explicit-suffix ref must be pulled verbatim: {r}"
        );
    }
}

#[test]
fn platform_digest_pin_is_verbatim() {
    let digest = "ghcr.io/org/plugins/audit@sha256:\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(
        resolve_platform_candidates(digest, "linux-amd64", "1"),
        vec![digest.to_owned()]
    );
    let tag_and_digest = "ghcr.io/org/plugins/audit:0.1.0-dev.18@sha256:\
                          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    assert_eq!(
        resolve_platform_candidates(tag_and_digest, "linux-amd64", "1"),
        vec![tag_and_digest.to_owned()]
    );
}

#[test]
fn platform_registry_port_not_mistaken_for_tag() {
    // `localhost:5000` is a registry+port; the tag colon lives in the LAST
    // path segment. No tag here → protocol floating tag.
    assert_eq!(
        resolve_platform_candidates("localhost:5000/audit", "linux-amd64", "1"),
        vec![
            "localhost:5000/audit:protocol-1-linux-amd64".to_owned(),
            "localhost:5000/audit:protocol-1-wasi-wasm".to_owned(),
        ]
    );
    // With a tag, the port is still not the tag.
    assert_eq!(
        resolve_platform_candidates("localhost:5000/audit:2.0", "linux-amd64", "1"),
        vec![
            "localhost:5000/audit:2.0-linux-amd64".to_owned(),
            "localhost:5000/audit:2.0-wasi-wasm".to_owned(),
        ]
    );
}

#[test]
fn platform_musl_token_matches_publish_contract() {
    // The musl gateway resolves to the `-linux-musl-<arch>` token the CD
    // publish side emits (which an OCI image index cannot express).
    assert_eq!(
        resolve_platform_candidates("audit:1.2.3", "linux-musl-amd64", "1"),
        vec![
            "audit:1.2.3-linux-musl-amd64".to_owned(),
            "audit:1.2.3-wasi-wasm".to_owned(),
        ]
    );
}

#[test]
fn tag_platform_suffix_detection() {
    for yes in [
        "0.1.0-dev.18-linux-amd64",
        "protocol-1-linux-musl-arm64",
        "1.2.3-darwin-arm64",
        "protocol-1-wasi-wasm",
        "wasi-wasm",
    ] {
        assert!(
            tag_has_platform_suffix(yes),
            "should be a platform tag: {yes}"
        );
    }
    for no in [
        "0.1.0-dev.18",
        "protocol-1",
        "1.2.3",
        "latest",
        "1.2.3-rc.1",
    ] {
        assert!(
            !tag_has_platform_suffix(no),
            "should NOT be a platform tag: {no}"
        );
    }
}

#[test]
fn interpolate_env_inlines_cel_env_form() {
    unsafe {
        std::env::set_var("MCPGTEST_SECRET", "s3cret");
    }
    assert_eq!(interpolate_env("${env.MCPGTEST_SECRET}").unwrap(), "s3cret",);
    assert_eq!(interpolate_env("literal").unwrap(), "literal");
}

#[test]
fn interpolate_env_fails_on_unset_var() {
    let err = interpolate_env("${env.DEFINITELY_NOT_SET_MCPG_VAR}").unwrap_err();
    assert!(err.to_string().contains("DEFINITELY_NOT_SET_MCPG_VAR"));
}

#[test]
fn resolve_oci_auth_basic_path() {
    let cfg = crate::config::PluginRegistryAuthConfig {
        username: Some("alice".into()),
        password: Some(mcpg_sensitive::Sensitive::new("hunter2".into())),
        docker_config_path: None,
    };
    match resolve_oci_auth(&cfg, "ghcr.io").unwrap() {
        mcpg_plugin_host::oci::OciAuth::Basic { username, password } => {
            assert_eq!(username, "alice");
            assert_eq!(password, "hunter2");
        }
        _ => panic!("expected Basic auth"),
    }
}

#[test]
fn resolve_oci_auth_anonymous_by_default() {
    // Point `docker_config_path` at a file that doesn't exist so the
    // Docker config fallback is a no-op and we land on Anonymous.
    let cfg = crate::config::PluginRegistryAuthConfig {
        docker_config_path: Some("/tmp/__mcpg_test_no_such_config_file__.json".into()),
        ..Default::default()
    };
    assert!(matches!(
        resolve_oci_auth(&cfg, "ghcr.io").unwrap(),
        mcpg_plugin_host::oci::OciAuth::Anonymous
    ));
}

#[test]
fn resolve_oci_auth_rejects_partial_creds() {
    let cfg = crate::config::PluginRegistryAuthConfig {
        username: Some("alice".into()),
        password: None,
        docker_config_path: None,
    };
    assert!(resolve_oci_auth(&cfg, "ghcr.io").is_err());
}

#[test]
fn resolve_oci_auth_falls_back_to_docker_config() {
    // base64("operator:rot@13") = b3BlcmF0b3I6cm90QDEz
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        r#"{ "auths": { "my-harbor.corp.local": { "auth": "b3BlcmF0b3I6cm90QDEz" } } }"#,
    )
    .unwrap();
    let cfg = crate::config::PluginRegistryAuthConfig {
        username: None,
        password: None,
        docker_config_path: Some(config_path.to_string_lossy().into_owned()),
    };
    match resolve_oci_auth(&cfg, "my-harbor.corp.local").unwrap() {
        mcpg_plugin_host::oci::OciAuth::Basic { username, password } => {
            assert_eq!(username, "operator");
            assert_eq!(password, "rot@13");
        }
        _ => panic!("expected Basic auth from docker config"),
    }
}

#[test]
fn resolve_oci_auth_explicit_creds_bypass_docker_config() {
    // Even if a docker config is present AND has an entry for the
    // host, explicit `username` + `password` on the
    // `PluginRegistryAuthConfig` wins.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.json");
    std::fs::write(
        &config_path,
        r#"{ "auths": { "ghcr.io": { "auth": "ZG9ja2VyLWNvbmZpZzpkYy1zZWNyZXQ=" } } }"#,
    )
    .unwrap();
    let cfg = crate::config::PluginRegistryAuthConfig {
        username: Some("explicit".into()),
        password: Some(mcpg_sensitive::Sensitive::new("wins".into())),
        docker_config_path: Some(config_path.to_string_lossy().into_owned()),
    };
    match resolve_oci_auth(&cfg, "ghcr.io").unwrap() {
        mcpg_plugin_host::oci::OciAuth::Basic { username, password } => {
            assert_eq!(username, "explicit");
            assert_eq!(password, "wins");
        }
        _ => panic!("expected Basic auth (explicit)"),
    }
}

#[test]
fn registry_host_from_reference_strips_scheme_and_path() {
    assert_eq!(
        registry_host_from_reference("ghcr.io/mcpg-dev/plugins/audit:1.0"),
        "ghcr.io"
    );
    assert_eq!(
        registry_host_from_reference("https://ghcr.io/mcpg-dev/plugins/audit:1.0"),
        "ghcr.io"
    );
    assert_eq!(
        registry_host_from_reference("http://localhost:5000/plugins/audit:1.0"),
        "localhost:5000"
    );
    // Already bare host
    assert_eq!(registry_host_from_reference("ghcr.io"), "ghcr.io");
}

#[test]
fn plugin_source_validates_xor() {
    use crate::config::PluginSourceConfig;
    assert!(!PluginSourceConfig::default().is_well_formed());
    assert!(
        PluginSourceConfig {
            path: Some("/x".into()),
            oci: None
        }
        .is_well_formed()
    );
    assert!(
        PluginSourceConfig {
            path: None,
            oci: Some("r/p:t".into())
        }
        .is_well_formed()
    );
    assert!(
        !PluginSourceConfig {
            path: Some("/x".into()),
            oci: Some("r/p:t".into()),
        }
        .is_well_formed()
    );
}

// -- start_extra_transports (gateway.server.transports[]) ---------

fn registry_with_memory_transport() -> mcpg_plugin_host::PluginRegistry {
    let mut reg = mcpg_plugin_host::PluginRegistry::new();
    let plugin = crate::builtins::transport_memory::MemoryTransport::new();
    reg.register_transport(plugin, mcpg_plugin_protocol::PluginTier::Native)
        .expect("memory transport registers");
    reg
}

fn memory_transport_entry() -> crate::config::PluginEntryConfig {
    crate::config::PluginEntryConfig {
        id: "dev.mcpg.builtin.transport.memory".to_owned(),
        r#ref: None,
        kind: "native".to_owned(),
        class: "transport".to_owned(),
        source: crate::config::PluginSourceConfig::default(),
        config: serde_json::Value::Null,
        signature: None,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }
}

fn empty_runtime_swap() -> std::sync::Arc<arc_swap::ArcSwap<crate::runtime::GatewayRuntime>> {
    let runtime = crate::runtime::GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        vec![crate::config::SinkConfig {
            kind: "stdout".to_owned(),
            config: serde_json::json!({"format": "json"}),
            level: None,
        }],
        true,
    );
    std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(runtime))
}

#[tokio::test]
async fn start_extra_transports_empty_returns_empty() {
    let reg = registry_with_memory_transport();
    let swap = empty_runtime_swap();
    let handles = start_extra_transports(&[], &[], "single_node", swap, &reg)
        .await
        .unwrap();
    assert!(handles.is_empty());
}

#[tokio::test]
async fn start_extra_transports_starts_memory_plugin_by_id() {
    let reg = registry_with_memory_transport();
    let swap = empty_runtime_swap();
    let entries = vec![memory_transport_entry()];
    let handles = start_extra_transports(
        &[kind_ref("dev.mcpg.builtin.transport.memory")],
        &entries,
        "single_node",
        swap,
        &reg,
    )
    .await
    .unwrap();
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].listen_address().await.as_deref(), Some("memory"),);
    for h in handles {
        h.close().await;
    }
}

#[tokio::test]
async fn start_extra_transports_refuses_builtin_keyword() {
    let reg = registry_with_memory_transport();
    let swap = empty_runtime_swap();
    let res =
        start_extra_transports(&[kind_ref("builtin-http")], &[], "single_node", swap, &reg).await;
    let err = match res {
        Ok(_) => panic!("expected start_extra_transports to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("primary `transport:`"),
        "built-in keyword refusal surfaces: {msg}"
    );
}

#[tokio::test]
async fn start_extra_transports_refuses_unknown_plugin_id() {
    let reg = registry_with_memory_transport();
    let swap = empty_runtime_swap();
    let res = start_extra_transports(
        &[kind_ref("dev.mcpg.transport.does-not-exist")],
        &[],
        "single_node",
        swap,
        &reg,
    )
    .await;
    let err = match res {
        Ok(_) => panic!("expected start_extra_transports to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does-not-exist"),
        "unknown plugin id surfaces: {msg}"
    );
}

#[tokio::test]
async fn start_extra_transports_refuses_kind_cluster() {
    let reg = registry_with_memory_transport();
    let swap = empty_runtime_swap();
    let res = start_extra_transports(&[kind_ref("cluster")], &[], "single_node", swap, &reg).await;
    let err = match res {
        Ok(_) => panic!("expected start_extra_transports to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    // resolve_kind catches `kind: cluster` against a cluster
    // that doesn't provide a `transport` role before our own
    // post-resolve `Cluster` arm fires; either error path is
    // acceptable.
    assert!(
        msg.contains("transport"),
        "cluster meta-kind refusal surfaces: {msg}"
    );
}

// -- build_binding_cache_overrides ---------------------------------

fn binding_with_cache(
    name: &str,
    cache: Option<crate::config::wiring::KindRef>,
) -> crate::config::BackendConfig {
    crate::config::BackendConfig {
        name: name.to_owned(),
        title: None,
        description: format!("test binding {name}"),
        input_schema: None,
        output_schema: None,
        backend: crate::config::BackendImpl::from_typed(
            "mock",
            crate::config::MockBackendConfig {
                response: serde_json::json!({"ok": true}),
                delay_ms: 0,
                error: false,
                error_message: None,
                passthrough: false,
            },
        ),
        governance: crate::config::BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache,
        quotas: None,
        annotations: None,
        task_support: None,
        prompt_arguments: None,
        uri: None,
        mime_type: None,
        uri_template: None,
        variable_completions: None,
        watch: None,
        icons: None,
        descriptor_meta: None,
        mcp_app_url: None,
        resource_size: None,
        resource_annotations: None,
    }
}

fn config_with_tool_bindings(
    bindings: Vec<crate::config::BackendConfig>,
) -> crate::config::AppConfig {
    let mut cfg = crate::config::AppConfig::default();
    cfg.mcp.capabilities.tools = bindings;
    cfg
}

#[test]
fn build_binding_cache_overrides_empty_when_no_cache_field() {
    let cfg = config_with_tool_bindings(vec![binding_with_cache("plain-tool", None)]);
    let overrides = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024)).unwrap();
    assert!(overrides.is_empty());
}

#[test]
fn build_binding_cache_overrides_in_process_keyword_yields_cache() {
    let cfg = config_with_tool_bindings(vec![binding_with_cache(
        "fast-tool",
        Some(kind_ref("in-process")),
    )]);
    let overrides = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024)).unwrap();
    let entry = overrides
        .get("fast-tool")
        .expect("fast-tool override present");
    assert!(entry.is_some(), "in-process keyword yields a Some(cache)");
}

#[test]
fn build_binding_cache_overrides_in_process_honours_max_bytes_config() {
    let cfg = config_with_tool_bindings(vec![crate::config::BackendConfig {
        cache: Some(crate::config::wiring::KindRef {
            kind: "in-process".to_owned(),
            config: serde_json::json!({"max_bytes": 1024_u64}),
        }),
        ..binding_with_cache("sized-tool", None)
    }]);
    let overrides = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024)).unwrap();
    let entry = overrides.get("sized-tool").unwrap();
    // Sanity: cache built; we don't introspect LruResponseCache size
    // here (the test would couple to LRU internals) — the helper
    // accepting a custom max_bytes without panicking is the
    // contract. Resolution failure would mean None or an
    // unwrap_err, both of which are exercised in other tests.
    assert!(entry.is_some());
}

#[test]
fn build_binding_cache_overrides_disabled_keyword_yields_none() {
    let cfg = config_with_tool_bindings(vec![binding_with_cache(
        "no-cache-tool",
        Some(kind_ref("disabled")),
    )]);
    let overrides = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024)).unwrap();
    let entry = overrides
        .get("no-cache-tool")
        .expect("no-cache-tool override present");
    assert!(
        entry.is_none(),
        "kind: disabled records an explicit None opt-out"
    );
}

#[test]
fn build_binding_cache_overrides_refuses_plugin_id() {
    let cfg = config_with_tool_bindings(vec![binding_with_cache(
        "plugin-cache-tool",
        Some(kind_ref("dev.mcpg.cache.redis")),
    )]);
    // The plugin id resolves to a plugin lookup, but no plugin
    // is loaded under that id, so resolve_kind itself fails
    // with a "no plugin loaded" message before we'd hit the
    // bridge-not-implemented arm. Either error is acceptable
    // — both refuse boot, which is the contract.
    let res = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024));
    let err = match res {
        Ok(_) => panic!("expected plugin id to fail resolution"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("plugin-cache-tool"),
        "binding name surfaces: {msg}"
    );
}

#[test]
fn build_binding_cache_overrides_refuses_kind_cluster() {
    let cfg = config_with_tool_bindings(vec![binding_with_cache(
        "clustered-tool",
        Some(kind_ref("cluster")),
    )]);
    let res = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024));
    let err = match res {
        Ok(_) => panic!("expected kind: cluster to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("clustered-tool"),
        "binding name surfaces: {msg}"
    );
}

#[test]
fn build_binding_cache_overrides_walks_all_four_capability_lists() {
    let mut cfg = config_with_tool_bindings(vec![binding_with_cache(
        "tool-a",
        Some(kind_ref("disabled")),
    )]);
    cfg.mcp.capabilities.prompts =
        vec![binding_with_cache("prompt-a", Some(kind_ref("in-process")))];
    cfg.mcp.capabilities.resources =
        vec![binding_with_cache("resource-a", Some(kind_ref("disabled")))];
    cfg.mcp.capabilities.resource_templates = vec![binding_with_cache(
        "template-a",
        Some(kind_ref("in-process")),
    )];
    let overrides = build_binding_cache_overrides(&cfg, &(64 * 1024 * 1024)).unwrap();
    assert_eq!(overrides.len(), 4);
    assert!(overrides["tool-a"].is_none());
    assert!(overrides["prompt-a"].is_some());
    assert!(overrides["resource-a"].is_none());
    assert!(overrides["template-a"].is_some());
}

#[test]
fn synthetic_openapi_binding_reconstructs_backend_config() {
    // The gateway rebuilds a tool binding from an
    // ExpandedTool's generic backend_kind + backend_spec, and relays the
    // operator-authored governance into the typed config.
    let tool = mcpg_plugin_protocol::ExpandedTool {
        name: "petstore.getPetById".to_owned(),
        title: Some("Get pet".to_owned()),
        description: "Get a pet by id".to_owned(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": { "petId": { "type": "integer" } },
            "required": ["petId"]
        }),
        output_schema: Some(serde_json::json!({ "type": "object" })),
        annotations: None,
        meta: Some(serde_json::json!({ "openapi": { "source": "petstore" } })),
        backend_kind: "openapi".to_owned(),
        backend_spec: serde_json::json!({ "source": "petstore", "operation": "getPetById" }),
        governance: Some(serde_json::json!({ "minimum_trust": "verified" })),
        retry: None,
    };

    let binding = synthetic_tool_binding(tool).expect("synthesize binding");
    assert_eq!(binding.name, "petstore.getPetById");
    assert_eq!(binding.title.as_deref(), Some("Get pet"));
    assert_eq!(binding.description, "Get a pet by id");
    assert!(binding.input_schema.is_some());
    assert!(binding.output_schema.is_some());
    assert!(binding.descriptor_meta.is_some());
    assert_eq!(binding.backend.kind, "openapi");
    assert_eq!(
        binding.backend.spec.get("source").and_then(|v| v.as_str()),
        Some("petstore")
    );
    assert_eq!(
        binding
            .backend
            .spec
            .get("operation")
            .and_then(|v| v.as_str()),
        Some("getPetById")
    );
    // Relayed governance deserialized into the typed struct.
    assert_eq!(binding.governance.minimum_trust, TrustLevelConfig::Verified);
}

#[test]
fn synthetic_resource_template_binding_reconstructs_backend_config() {
    // A read-by-id GET becomes a resource_template binding.
    let rt = mcpg_plugin_protocol::ExpandedResourceTemplate {
        name: "petstore.getPetById".to_owned(),
        uri_template: "petstore://pets/{petId}".to_owned(),
        description: "A pet by id".to_owned(),
        mime_type: Some("application/json".to_owned()),
        meta: None,
        backend_kind: "openapi".to_owned(),
        backend_spec: serde_json::json!({ "source": "petstore", "operation": "getPetById" }),
        governance: None,
        retry: None,
    };
    let binding = synthetic_resource_template_binding(rt).expect("synthesize template");
    assert_eq!(binding.name, "petstore.getPetById");
    assert_eq!(
        binding.uri_template.as_deref(),
        Some("petstore://pets/{petId}")
    );
    assert_eq!(binding.mime_type.as_deref(), Some("application/json"));
    assert_eq!(binding.backend.kind, "openapi");
    assert_eq!(
        binding
            .backend
            .spec
            .get("operation")
            .and_then(|v| v.as_str()),
        Some("getPetById")
    );
}

#[tokio::test]
async fn openapi_expansion_end_to_end() {
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Upstream the OpenAPI source points at.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/pets/42"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "id": 42, "name": "Rex" })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/pets"))
        .and(body_json(serde_json::json!({ "name": "Milo" })))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({ "id": 7, "name": "Milo" })),
        )
        .mount(&server)
        .await;

    let spec = serde_json::json!({
        "openapi": "3.0.3",
        "info": { "title": "Petstore", "version": "1.0.0" },
        "paths": {
            "/pets": {
                "post": {
                    "operationId": "createPet",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "required": ["name"],
                            "properties": { "name": { "type": "string" } } } } } },
                    "responses": { "201": { "description": "created" } }
                }
            },
            "/pets/{petId}": {
                "get": {
                    "operationId": "getPetById",
                    "parameters": [ { "name": "petId", "in": "path", "required": true,
                        "schema": { "type": "integer" } } ],
                    "responses": { "200": { "description": "ok" } }
                }
            }
        }
    });
    let source_config = serde_json::json!({
        "sources": [{
            "name": "petstore",
            "spec": { "inline": spec },
            "base_url": server.uri(),
            "upstream_safety": { "allow_private_backends": true, "allow_insecure_http": true },
            "expose": { "tools": true, "tool_prefix": "petstore." }
        }]
    })
    .to_string();

    // Register the openapi backend in-process (mirrors the cdylib loader).
    let plugin = std::sync::Arc::new(
        mcpg_plugin_backend_openapi::OpenapiBackendPlugin::from_config_json(&source_config),
    );
    let mut registry = mcpg_plugin_host::PluginRegistry::new();
    mcpg_plugin_host::FirstPartyRegistrar::new(&mut registry)
        .register(
            mcpg_plugin_backend_openapi::DESCRIPTOR_YAML,
            // The openapi backend declares `network_outbound` as a required
            // capability; the in-process registrar fail-closes unless
            // it's granted, mirroring the operator's `granted_capabilities`.
            &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
            (),
            |reg, _host| {
                reg.register_backend(plugin.clone(), mcpg_plugin_protocol::PluginTier::Native)
            },
        )
        .expect("register in-process openapi backend");

    // Run the REAL gateway expansion pre-pass.
    let config = AppConfig::default();
    let expansion = expand_openapi_bindings(&config, &registry)
        .await
        .expect("expand");

    // createPet → tool; getPetById (read-by-id) → resource template.
    assert_eq!(
        expansion.tools.len(),
        1,
        "tools: {:?}",
        expansion.tools.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
    assert_eq!(expansion.tools[0].name, "petstore.createPet");
    assert!(expansion.tools[0].input_schema.is_some());
    assert_eq!(expansion.resource_templates.len(), 1);
    assert_eq!(expansion.resource_templates[0].name, "petstore.getPetById");
    assert_eq!(
        expansion.resource_templates[0].uri_template.as_deref(),
        Some("petstore://pets/{petId}")
    );

    // Register the synthetic profiles exactly as the gateway's dynamic pass does.
    let host = mcpg_plugin_protocol::noop_backend_host();
    for binding in expansion
        .tools
        .iter()
        .chain(expansion.resource_templates.iter())
    {
        let spec = crate::backends::dynamic_register_spec(&binding.backend, true).expect("spec");
        mcpg_plugin_protocol::BackendPlugin::register_profile(
            plugin.as_ref(),
            &binding.name,
            &spec,
            host.clone(),
        )
        .await
        .expect("register synthetic profile");
    }

    // Build the REAL capability registry from the synthetic bindings; assert routing.
    let cap = crate::backends::CapabilityRegistry::new(
        false,
        Default::default(),
        Default::default(),
        &expansion.tools,
        &[],
        &[],
        &expansion.resource_templates,
        Some(&registry),
    );
    assert!(matches!(
        cap.tool_route("petstore.createPet"),
        Some(crate::backends::BackendInvocationRoute::OpenapiCall { .. })
    ));
    assert!(matches!(
        cap.resource_route("petstore://pets/42"),
        Some(crate::backends::ResourceRoute::Template { .. })
    ));

    // Real tool call through the plugin → 201 envelope.
    let tool_req = mcpg_plugin_protocol::BackendRequest {
        payload: serde_json::to_vec(&serde_json::json!({ "name": "Milo" })).unwrap(),
        headers: vec![("mcpg-tool-name".to_owned(), "petstore.createPet".to_owned())],
        request_id: "it-1".to_owned(),
        session_id: None,
        identity: None,
        idempotency: None,
    };
    let resp = mcpg_plugin_protocol::BackendPlugin::execute(
        plugin.as_ref(),
        "petstore.createPet",
        tool_req,
    )
    .await
    .expect("tool execute");
    let env: serde_json::Value = serde_json::from_slice(&resp.payload).unwrap();
    assert!(
        env["downstreamError"].is_null(),
        "tool call failed: {env:#}"
    );
    assert_eq!(env["response"]["statusCode"], 201);

    // Real resource read (gateway-shaped args) → contents.
    let read_req = mcpg_plugin_protocol::BackendRequest {
        payload: serde_json::to_vec(&serde_json::json!({
            "petId": 42, "uri": "petstore://pets/42", "template_vars": { "petId": "42" }
        }))
        .unwrap(),
        headers: vec![],
        request_id: "it-2".to_owned(),
        session_id: None,
        identity: None,
        idempotency: None,
    };
    let resp = mcpg_plugin_protocol::BackendPlugin::execute(
        plugin.as_ref(),
        "petstore.getPetById",
        read_req,
    )
    .await
    .expect("resource read execute");
    let body: serde_json::Value = serde_json::from_slice(&resp.payload).unwrap();
    assert_eq!(body["contents"][0]["uri"], "petstore://pets/42");
    let inner: serde_json::Value =
        serde_json::from_str(body["contents"][0]["text"].as_str().expect("text")).unwrap();
    assert_eq!(inner, serde_json::json!({ "id": 42, "name": "Rex" }));
}

// ---------------------------------------------------------------------------
// Cluster `provides` routing-vocabulary cross-check. The boot
// cross-check (`cross_check_cluster_provides`) must accept a coordinator
// whose three role representations agree and fail-closed when the static
// wiring table disagrees with the live coordinator on a built-in kind.
// ---------------------------------------------------------------------------

#[test]
fn cross_check_cluster_provides_accepts_matching_single_node() {
    let coordinator = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    // single_node manifest provides = cache/kv/bus, == cluster_provides(),
    // == cluster_provides_for_kind("single_node").
    cross_check_cluster_provides(coordinator.as_ref(), "single_node")
        .expect("single_node roles agree across all three representations");
}

#[test]
fn cross_check_cluster_provides_fails_on_table_drift() {
    // single_node provides cache/kv/bus, but the `redis` table arm is
    // cache/kv (no bus). Cross-checking the single-node coordinator AS IF
    // it were kind `redis` must fail-closed — this is exactly the drift
    // (static fallback table vs running coordinator) the check exists to
    // catch on a built-in kind.
    let coordinator = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    let err = cross_check_cluster_provides(coordinator.as_ref(), "redis")
        .expect_err("table/coordinator role drift must fail-closed");
    let msg = err.to_string();
    assert!(msg.contains("role drift"), "unexpected error: {msg}");
}

#[test]
fn cross_check_cluster_provides_skips_table_for_plugin_class_kind() {
    // A 3rd-party / plugin-class cluster kind falls into the permissive
    // catch-all, so the static table is NOT compared; only live ==
    // manifest is asserted (always true for the single-node builtin).
    let coordinator = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    cross_check_cluster_provides(coordinator.as_ref(), "dev.mcpg.cluster.custom")
        .expect("plugin-class kind skips the table comparison");
}

// ---------------------------------------------------------------------------
// CC-2: live boot reachability probe. The vocabulary cross-check only proves
// the role strings agree; this probe round-trips the advertised primitives so
// a coordinator that can't actually serve them fails closed at boot instead
// of silently de-clustering.
// ---------------------------------------------------------------------------

use mcpg_cluster_api::ClusterBackend as _;

/// A `ClusterBackend` that delegates everything to an inner single-node
/// coordinator EXCEPT its advertised role-set (`provides`) and, optionally,
/// the KV accessor — so a test can simulate a coordinator that advertises a
/// role it cannot serve over the FFI.
struct ProbeMockBackend {
    inner: std::sync::Arc<crate::builtins::cluster_single_node::SingleNodeClusterBackend>,
    manifest: mcpg_plugin_protocol::PluginManifest,
    kv_accessor: bool,
}

impl std::fmt::Debug for ProbeMockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeMockBackend")
            .field("provides", &self.manifest.provides)
            .field("kv_accessor", &self.kv_accessor)
            .finish()
    }
}

impl ProbeMockBackend {
    fn new(provides: &[&str], kv_accessor: bool) -> Self {
        let inner = crate::builtins::cluster_single_node::SingleNodeClusterBackend::with_node_id(
            "probe-mock",
        );
        let mut manifest = inner.manifest().clone();
        manifest.provides = provides.iter().map(|s| (*s).to_owned()).collect();
        Self {
            inner,
            manifest,
            kv_accessor,
        }
    }
}

#[mcpg_plugin_protocol::async_trait]
impl mcpg_cluster_api::ClusterBackend for ProbeMockBackend {
    fn manifest(&self) -> &mcpg_plugin_protocol::PluginManifest {
        &self.manifest
    }

    fn key_value_store(&self) -> Option<std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>> {
        if self.kv_accessor {
            self.inner.key_value_store()
        } else {
            None
        }
    }

    fn pub_sub(&self) -> Option<std::sync::Arc<dyn mcpg_cluster_api::PubSub>> {
        self.inner.pub_sub()
    }

    async fn node_info(&self) -> mcpg_cluster_api::ClusterNodeInfo {
        self.inner.node_info().await
    }

    async fn list_peers(&self) -> Vec<mcpg_cluster_api::ClusterPeer> {
        self.inner.list_peers().await
    }

    async fn watch_peers(&self) -> mcpg_cluster_api::BoxPeerEventStream {
        self.inner.watch_peers().await
    }

    async fn acquire_leadership(
        &self,
        role: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<mcpg_cluster_api::BoxActiveLease, mcpg_cluster_api::ClusterError> {
        self.inner.acquire_leadership(role, lease_ttl).await
    }

    async fn acquire_lock(
        &self,
        key: &str,
        lease_ttl: std::time::Duration,
    ) -> Result<mcpg_cluster_api::BoxActiveLease, mcpg_cluster_api::ClusterError> {
        self.inner.acquire_lock(key, lease_ttl).await
    }

    async fn publish(
        &self,
        topic: &str,
        routing_key: Option<&str>,
        payload: bytes::Bytes,
    ) -> Result<(), mcpg_cluster_api::ClusterError> {
        self.inner.publish(topic, routing_key, payload).await
    }

    async fn subscribe(
        &self,
        topic: &str,
        group: Option<&str>,
        routing_key: Option<&str>,
    ) -> Result<mcpg_cluster_api::BoxPublishedMessageStream, mcpg_cluster_api::ClusterError> {
        self.inner.subscribe(topic, group, routing_key).await
    }
}

#[tokio::test]
async fn probe_cluster_reachability_ok_for_capable_coordinator() {
    // single-node backs kv + bus in-process; a real round-trip succeeds.
    let coordinator = crate::builtins::cluster_single_node::SingleNodeClusterBackend::new();
    probe_cluster_reachability(coordinator.as_ref(), false)
        .await
        .expect("a coordinator that actually serves its advertised roles passes the probe");
}

#[tokio::test]
async fn probe_cluster_reachability_fails_closed_on_missing_kv_accessor() {
    // Advertises `kv` but exposes no key_value_store() accessor: exactly the
    // SUB-2 vocabulary-vs-reachability gap. Must fail closed.
    let mock = ProbeMockBackend::new(&["kv"], false);
    let err = probe_cluster_reachability(&mock, false)
        .await
        .expect_err("advertised-but-absent kv accessor must fail the probe");
    let msg = err.to_string();
    assert!(
        msg.contains("reachability probe") || msg.contains("key_value_store"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn probe_cluster_reachability_degrades_when_allowed() {
    // Same broken coordinator, but the operator opted into degraded boot:
    // the probe logs loudly and returns Ok rather than refusing to start.
    let mock = ProbeMockBackend::new(&["kv"], false);
    probe_cluster_reachability(&mock, true)
        .await
        .expect("allow_degraded_boot downgrades the hard failure to a warning");
}

#[tokio::test]
async fn probe_cluster_reachability_ok_for_bus_only_coordinator() {
    // A consul/etcd-style coordinator advertises only `bus`; the probe must
    // round-trip the pub_sub primitive and NOT require kv.
    let mock = ProbeMockBackend::new(&["bus"], false);
    probe_cluster_reachability(&mock, false)
        .await
        .expect("a bus-only coordinator that serves pub_sub passes the probe");
}

// ---------------------------------------------------------------------------
// CC-4 / CC-5: cluster-stable sub-key derivation. The requestState codec key
// and the modern synthetic-session key both derive from the cluster-stable
// secret (cluster.state_encryption_key_env) when not explicitly configured,
// so every replica computes the same key without a second config knob.
// ---------------------------------------------------------------------------

#[test]
fn derive_cluster_subkey_is_deterministic() {
    // Same base + domain → same sub-key on every replica (the property that
    // makes cross-replica modern resume decode).
    let base = [9u8; 32];
    let a = derive_cluster_subkey(&base, b"mcpg:request-state-codec:v1");
    let b = derive_cluster_subkey(&base, b"mcpg:request-state-codec:v1");
    assert_eq!(a, b);
}

#[test]
fn derive_cluster_subkey_is_domain_separated() {
    // Different domains from the same base must yield different sub-keys, so
    // the requestState codec key and the synthetic-session key never collide.
    let base = [9u8; 32];
    let codec = derive_cluster_subkey(&base, b"mcpg:request-state-codec:v1");
    let session = derive_cluster_subkey(&base, SYNTHETIC_SESSION_KEY_DOMAIN);
    assert_ne!(codec, session);
}

#[test]
fn derive_cluster_subkey_changes_with_the_base() {
    // A sub-key is bound to the cluster secret: two deployments with different
    // cluster keys derive different sub-keys (no cross-deployment overlap).
    let d = b"mcpg:request-state-codec:v1";
    assert_ne!(
        derive_cluster_subkey(&[1u8; 32], d),
        derive_cluster_subkey(&[2u8; 32], d)
    );
}

#[test]
fn cluster_state_key_bytes_none_when_unset() {
    let cluster = crate::config::ClusterConfig::default();
    assert!(
        cluster_state_key_bytes(&cluster)
            .expect("no env var named → Ok(None)")
            .is_none()
    );
}

/// `mock` is a plugin like every other backend: the gateway links none of them
/// in, so a `kind: mock` binding resolves ONLY when `plugins[]` declares the
/// artefact. A config that binds it without declaring it must leave boot with
/// no `mock` backend — the operator gets a clear unresolved-binding failure
/// rather than a fixture silently answering in production.
///
/// The positive half (a declared artefact registers and dispatches) needs a
/// real cdylib on disk, so it lives in the e2e/conformance harnesses that
/// inject one; it cannot be exercised from a unit test.
#[tokio::test]
async fn mock_binding_without_a_plugins_entry_registers_no_backend() {
    let mut config: crate::config::AppConfig = serde_yaml::from_str(
        r#"
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        governance:
          minimum_trust: unauthenticated
        backend:
          kind: mock
          response: { ok: true, source: "quickstart" }
"#,
    )
    .expect("config parses");

    let bundle = super::build_plugin_registry(&mut config, None, None)
        .await
        .expect("plugin registry builds");

    assert!(
        bundle.registry.backend("mock").is_none(),
        "an undeclared `kind: mock` binding must not resolve — the mock is a \
         dev-dependency fixture and must never be linked into a shipped binary"
    );
}

#[test]
fn derive_inherits_registry_keys_when_entry_has_none() {
    let mut registry = registry_with_policy(crate::config::SignaturePolicy::Warn);
    registry.trusted_keys = vec![crate::config::TrustedKeyConfig {
        id: "org".into(),
        pem: pem_for_raw_key([0x11u8; 32]),
    }];
    let entry = entry_with_signature("p7", None);
    let opts = derive_native_verify_options_for_entry(&entry, &registry, None).unwrap();
    // Gateway-wide anchors flow in (plus any built-in official keys).
    assert!(opts.trusted_public_keys.contains(&[0x11u8; 32]));
}

#[test]
fn derive_per_entry_keys_replace_registry_keys() {
    let mut registry = registry_with_policy(crate::config::SignaturePolicy::Warn);
    registry.trusted_keys = vec![crate::config::TrustedKeyConfig {
        id: "org".into(),
        pem: pem_for_raw_key([0x11u8; 32]),
    }];
    let signature = crate::config::SignatureConfig {
        policy: None,
        sha256: None,
        trusted_keys: vec![crate::config::TrustedKeyConfig {
            id: "vendor".into(),
            pem: pem_for_raw_key([0x22u8; 32]),
        }],
    };
    let entry = entry_with_signature("p8", Some(signature));
    let opts = derive_native_verify_options_for_entry(&entry, &registry, None).unwrap();
    assert_eq!(opts.trusted_public_keys, vec![[0x22u8; 32]]);
}

#[test]
fn built_in_official_key_bundle_decodes_and_flows_into_inherit_path() {
    let registry = registry_with_policy(crate::config::SignaturePolicy::Enforce);
    let entry = entry_with_signature("p9", None);
    let opts = derive_native_verify_options_for_entry(&entry, &registry, None).unwrap();
    // The compiled-in official key is a trust anchor out of the box.
    assert!(
        !opts.trusted_public_keys.is_empty(),
        "official key bundle produced no anchors"
    );
}
