use std::fs;

use super::debug::{DEFAULT_COMMAND_PROFILE, DEFAULT_NETWORK_PROFILE};
use super::*;

/// Serializes the tests that touch process env — writers AND readers.
///
/// Env is per-process, not per-test, and the harness runs these on many
/// threads. `AppConfig::load_sources` consults env, so a test that set
/// `MCPG_GATEWAY__SERVER__BIND_ADDRESS` was observed by any *other* test
/// loading a config at that moment — the failures surfaced in the readers,
/// not in the test that did the mutating, and moved between runs.
/// Guarding only the writers is therefore not enough: every test that
/// loads config through an env-consulting entry point must hold this too.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The crate directory, or the runfiles copy of it under a sandboxed runner.
///
/// `CARGO_MANIFEST_DIR` is baked in at compile time and names a path that no
/// longer exists when the test runs somewhere else, so a runner that stages
/// data as runfiles sets `MCPG_TEST_DATA_DIR` to where it actually put them.
/// Unset under `cargo test`, which keeps the manifest path.
fn data_dir() -> std::path::PathBuf {
    match (
        std::env::var("MCPG_TEST_DATA_DIR"),
        std::env::var("TEST_SRCDIR"),
    ) {
        (Ok(rel), Ok(root)) => std::path::PathBuf::from(root).join(rel),
        _ => std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
    }
}

/// A directory the test may WRITE to. The crate directory is read-only under a
/// sandboxed runner, and `TEST_TMPDIR` is the runner's answer to that.
fn scratch_dir() -> std::path::PathBuf {
    std::env::var("TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".tmp-tests"))
}

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    // A test that panics mid-mutation poisons the lock; the env damage is
    // already done and re-poisoning every later test would hide the real
    // failure, so take the guard regardless.
    ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[test]
fn load_from_yaml_strs_later_overrides_earlier_top_level_field() {
    // Two YAML "files" set the same scalar. Later wins.
    let base = "gateway:\n  server:\n    bind_address: \"127.0.0.1:8787\"\n";
    let prod = "gateway:\n  server:\n    bind_address: \"0.0.0.0:443\"\n";
    let cfg = AppConfig::load_from_yaml_strs(&[base, prod]).expect("merge");
    assert_eq!(cfg.gateway.server.bind_address, "0.0.0.0:443");
}

#[test]
fn load_sources_merges_a_file_then_an_inline_overlay() {
    let _env = env_guard();
    // A file base layer, then an inline (remote/base64) overlay that wins —
    // the same later-wins semantics as multiple files, so a URL/base64
    // `--config` layer behaves exactly like a file layer.
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("base.yaml");
    fs::write(
        &base_path,
        "gateway:\n  server:\n    bind_address: \"127.0.0.1:8787\"\n    request_timeout_ms: 1000\n",
    )
    .unwrap();
    let overlay = "gateway:\n  server:\n    bind_address: \"0.0.0.0:443\"\n";
    let cfg = AppConfig::load_sources(&[
        ConfigSource::File(base_path),
        ConfigSource::Inline {
            origin: "base64:<inline>".to_owned(),
            yaml: overlay.to_owned(),
        },
    ])
    .expect("merge");
    // Overlay overrode the address…
    assert_eq!(cfg.gateway.server.bind_address, "0.0.0.0:443");
    // …but the base's other field survives (deep merge, not replace).
    assert_eq!(cfg.gateway.server.request_timeout_ms, 1000);
}

#[test]
fn load_sources_reports_a_missing_file_layer() {
    let _env = env_guard();
    let err = AppConfig::load_sources(&[ConfigSource::File("/no/such/config.yaml".into())])
        .expect_err("missing file");
    assert!(err.to_string().contains("config file not found"), "{err}");
}

#[test]
fn load_from_yaml_strs_deep_merges_nested_maps() {
    // Nested maps merge key-by-key — fields the override doesn't
    // mention come from the base. Critical operator UX: the override
    // file shouldn't have to repeat every base field to "keep" it.
    let base = r#"
gateway:
  server:
    bind_address: "127.0.0.1:8787"
    health_path: "/healthz"
"#;
    let prod = r#"
gateway:
  server:
    bind_address: "0.0.0.0:443"
"#;
    let cfg = AppConfig::load_from_yaml_strs(&[base, prod]).expect("merge");
    assert_eq!(cfg.gateway.server.bind_address, "0.0.0.0:443"); // overridden
    assert_eq!(cfg.gateway.server.health_path, "/healthz"); // preserved from base
}

#[test]
fn load_from_yaml_strs_arrays_replace_wholesale() {
    // Arrays don't merge element-by-element — the override's array
    // wins entirely. This is figment's default, and matches operator
    // expectation (`mcp.capabilities.tools: [a, b]` in override means
    // "exactly those two", not "a, b appended to whatever base had").
    let base = r#"
mcp:
  capabilities:
    tools:
      - name: tool.a
        description: from base
        backend:
          kind: mock
          response: "a"
"#;
    let prod = r#"
mcp:
  capabilities:
    tools:
      - name: tool.b
        description: from override
        backend:
          kind: mock
          response: "b"
"#;
    let cfg = AppConfig::load_from_yaml_strs(&[base, prod]).expect("merge");
    assert_eq!(cfg.binding_count(), 1);
    assert_eq!(cfg.mcp.capabilities.tools[0].name, "tool.b");
}

#[test]
fn load_from_yaml_strs_empty_slice_returns_defaults() {
    let cfg = AppConfig::load_from_yaml_strs(&[]).expect("defaults");
    assert_eq!(cfg.gateway.server.bind_address, "127.0.0.1:8787");
}

#[test]
fn load_uses_defaults_without_file() {
    let _env = env_guard();
    let config = AppConfig::load(None).expect("config loads");

    assert!(!config.feature_flags.debug_tools_enabled);
    assert_eq!(config.gateway.server.bind_address, "127.0.0.1:8787");
    assert_eq!(config.gateway.server.health_path, "/health");
    assert_eq!(config.gateway.server.mcp_path, "/mcp");
    assert!(config.gateway.server.allowed_origins.is_empty());
    assert_eq!(config.gateway.server.replay_window_limit, 16);
    assert_eq!(config.gateway.server.session_idle_timeout_ms, 900_000);
    let command_profile = config
        .debug
        .tools
        .command_profiles
        .get(DEFAULT_COMMAND_PROFILE)
        .expect("default command profile");
    assert_eq!(command_profile.command, "printf");
    assert_eq!(command_profile.timeout_ms, 2_000);
    assert_eq!(command_profile.max_output_bytes, 4_096);
    let network_profile = config
        .debug
        .tools
        .network_profiles
        .get(DEFAULT_NETWORK_PROFILE)
        .expect("default network profile");
    assert_eq!(network_profile.url, "http://127.0.0.1:8787/health");
    assert_eq!(network_profile.timeout_ms, 2_000);
    assert_eq!(network_profile.max_response_bytes, 4_096);
    assert_eq!(network_profile.expected_status_codes, vec![200]);
    assert!(!network_profile.require_json_response);
    assert!(network_profile.headers.is_empty());
    assert_eq!(config.binding_count(), 0);
    assert_eq!(
        config.debug.tools.bindings.command_probe_profile,
        DEFAULT_COMMAND_PROFILE
    );
    assert_eq!(
        config.debug.tools.bindings.network_probe_profile,
        DEFAULT_NETWORK_PROFILE
    );
    assert!(config.debug.tools.exposure.command_probe);
    assert!(config.debug.tools.exposure.network_probe);
    assert!(config.debug.tools.exposure.operational_overview_prompt);
    assert!(config.debug.tools.exposure.runtime_overview_resource);
    assert_eq!(config.observability.logs.level, "info");
    assert_eq!(config.observability.logs.sinks[0].kind, "stderr");
    assert_eq!(
        config.governance.policy.tool_access.default_minimum_trust,
        TrustLevelConfig::HeaderAsserted
    );
    assert_eq!(config.governance.policy.tool_access.cel_allow_if, None);
    assert!(config.governance.policy.tool_access.rules.is_empty());
}

#[test]
fn example_config_parses_and_validates() {
    // `config.example.yaml` is the canonical operator-facing
    // example. Every binding shape that ships in the mcpg CLI
    // must parse cleanly and pass `validate()` — this test is
    // the canary that catches drift.
    let path = data_dir().join("config.example.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read example config");
    let cfg = AppConfig::load_from_yaml_str(&yaml).expect("parse+validate example");
    assert!(cfg.binding_count() > 0);
    assert!(
        cfg.all_bindings().any(|(_, b)| b.backend.kind == "sql"),
        "example config must exercise the SQL binding shape"
    );
}

/// Every SQL-binding-focused sample under `examples/` must parse
/// plus validate. These configs are shipped as the operator-facing
/// how-to for features in the SQL binding — if one drifts, this
/// test surfaces it before the sample breaks for a real user.
#[test]
fn sql_binding_samples_parse_and_validate() {
    // examples/ sits beside this crate in a standalone checkout, and two
    // levels up in the workspace — prefer whichever exists.
    let samples_dir = match std::env::var("MCPG_TEST_EXAMPLES_DIR") {
        Ok(rel) => {
            std::path::PathBuf::from(std::env::var("TEST_SRCDIR").unwrap_or_default()).join(rel)
        }
        Err(_) => {
            let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let local = manifest.join("examples");
            if local.is_dir() {
                local
            } else {
                manifest
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.join("examples"))
                    .expect("workspace root from apps/gateway manifest")
            }
        }
    };
    for folder in [
        "26-sql-sqlite-todos",
        "27-sql-dynamic-resource-listings",
        "28-sql-pipeline-tx",
        "29-sql-await-job",
    ] {
        let path = samples_dir.join(folder).join("config.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {folder}/config.yaml: {e}"));
        let cfg = AppConfig::load_from_yaml_str(&yaml)
            .unwrap_or_else(|e| panic!("parse+validate {folder}: {e}"));
        assert!(
            cfg.binding_count() > 0,
            "{folder}: bindings list must not be empty"
        );
    }
}

#[test]
fn load_merges_yaml_file() {
    let _env = env_guard();
    let fixture_dir = scratch_dir();
    let _ = fs::create_dir_all(&fixture_dir);
    let path = fixture_dir.join(format!(
        "mcpg-config-{}-{}.yaml",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    fs::write(
        &path,
        r#"gateway:
    server:
        bind_address: 127.0.0.1:9900
        health_path: /status
        mcp_path: /gateway/mcp
        allowed_origins:
            - http://localhost:3000
        replay_window_limit: 32
        session_idle_timeout_ms: 1800
feature_flags:
    debug_tools_enabled: true
debug:
    tools:
        command_profiles:
            default_command_probe:
                command: /usr/bin/printf
                args:
                    - debug-command\n
                timeout_ms: 3000
                max_output_bytes: 128
        network_profiles:
            default_network_probe:
                url: http://127.0.0.1:9910/debug
                timeout_ms: 1500
                max_response_bytes: 256
                expected_status_codes:
                    - 200
                    - 202
                require_json_response: true
                headers:
                    Authorization: Bearer test-token
                    X-Tenant: local-dev
        bindings:
            command_probe_profile: default_command_probe
            network_probe_profile: default_network_probe
        exposure:
            command_probe: true
            network_probe: true
mcp:
    capabilities:
        tools:
            - name: weather.get_forecast
              title: Weather Forecast
              description: Fetch the weather forecast
              backend:
                  kind: http
                  url: http://127.0.0.1:9910/weather
                  method: post
                  timeout_ms: 3000
                  max_response_bytes: 8192
                  expected_status_codes:
                      - 200
              governance:
                  minimum_trust: header_asserted
                  allow_if: 'principal_id == "user-1"'
observability:
    logs:
        level: debug
        sinks:
            - kind: stderr
              config:
                  format: pretty
governance:
    policy:
        tool_access:
            default_minimum_trust: header_asserted
            cel_allow_if: 'tool_name == "mcpg.runtime.snapshot" && trust_level == "header_asserted"'
            rules:
                - tool_name: mcpg.runtime.snapshot
                  minimum_trust: unauthenticated
                  cel_allow_if: 'principal_id == "user-1"'
"#,
    )
    .expect("config file written");

    let config = AppConfig::load(Some(&path)).expect("config loads from file");
    let _ = fs::remove_file(&path);

    assert!(config.feature_flags.debug_tools_enabled);
    assert_eq!(config.gateway.server.bind_address, "127.0.0.1:9900");
    assert_eq!(config.gateway.server.health_path, "/status");
    assert_eq!(config.gateway.server.mcp_path, "/gateway/mcp");
    assert_eq!(
        config.gateway.server.allowed_origins,
        vec!["http://localhost:3000"]
    );
    assert_eq!(config.gateway.server.replay_window_limit, 32);
    assert_eq!(config.gateway.server.session_idle_timeout_ms, 1800);
    let command_profile = config
        .debug
        .tools
        .command_profiles
        .get(DEFAULT_COMMAND_PROFILE)
        .expect("default command profile");
    assert_eq!(command_profile.command, "/usr/bin/printf");
    assert_eq!(command_profile.args, vec!["debug-command\\n"]);
    assert_eq!(command_profile.timeout_ms, 3_000);
    assert_eq!(command_profile.max_output_bytes, 128);
    let network_profile = config
        .debug
        .tools
        .network_profiles
        .get(DEFAULT_NETWORK_PROFILE)
        .expect("default network profile");
    assert_eq!(network_profile.url, "http://127.0.0.1:9910/debug");
    assert_eq!(network_profile.timeout_ms, 1_500);
    assert_eq!(network_profile.max_response_bytes, 256);
    assert_eq!(network_profile.expected_status_codes, vec![200, 202]);
    assert!(network_profile.require_json_response);
    assert_eq!(
        network_profile.headers,
        std::collections::BTreeMap::from([
            ("Authorization".to_owned(), "Bearer test-token".to_owned()),
            ("X-Tenant".to_owned(), "local-dev".to_owned()),
        ])
    );
    assert_eq!(config.binding_count(), 1);
    let binding = &config.mcp.capabilities.tools[0];
    assert_eq!(binding.name, "weather.get_forecast");
    assert_eq!(binding.title.as_deref(), Some("Weather Forecast"));
    assert_eq!(binding.description, "Fetch the weather forecast");
    assert_eq!(
        binding.governance.allow_if.as_deref(),
        Some("principal_id == \"user-1\"")
    );
    assert_eq!(
        config.debug.tools.bindings.command_probe_profile,
        DEFAULT_COMMAND_PROFILE
    );
    assert_eq!(
        config.debug.tools.bindings.network_probe_profile,
        DEFAULT_NETWORK_PROFILE
    );
    assert!(config.debug.tools.exposure.command_probe);
    assert!(config.debug.tools.exposure.network_probe);
    assert!(config.debug.tools.exposure.operational_overview_prompt);
    assert!(config.debug.tools.exposure.runtime_overview_resource);
    assert_eq!(config.observability.logs.level, "debug");
    assert_eq!(config.observability.logs.sinks[0].kind, "stderr");
    assert_eq!(
        config.observability.logs.sinks[0]
            .config
            .get("format")
            .and_then(|v| v.as_str()),
        Some("pretty")
    );
    assert_eq!(
        config.governance.policy.tool_access.cel_allow_if.as_deref(),
        Some("tool_name == \"mcpg.runtime.snapshot\" && trust_level == \"header_asserted\"")
    );
    assert_eq!(
        config.governance.policy.tool_access.rules,
        vec![ToolTrustRuleConfig {
            tool_name: "mcpg.runtime.snapshot".to_owned(),
            minimum_trust: TrustLevelConfig::Unauthenticated,
            cel_allow_if: Some("principal_id == \"user-1\"".to_owned()),
            required_scopes: Vec::new(),
        }]
    );
}

#[test]
fn validate_rejects_invalid_health_path() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "health".to_owned(),
                mcp_path: "/mcp".to_owned(),
                allowed_origins: Vec::new(),
                replay_window_limit: 16,
                session_idle_timeout_ms: 900_000,
                shutdown_timeout_ms: 30_000,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_manual_policy_rule_for_binding() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfig {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: None,
                    rules: vec![ToolTrustRuleConfig {
                        tool_name: "test.tool".to_owned(),
                        minimum_trust: TrustLevelConfig::HeaderAsserted,
                        cel_allow_if: None,
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

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_backend_allow_if() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
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
                        allow_if: Some("   ".to_owned()),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_duplicate_binding_names() {
    let binding = BackendConfig {
        name: "test.tool".to_owned(),
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
        governance: BackendGovernanceConfig::default(),
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
    };
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![binding.clone(), binding],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_invalid_mcp_path() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "/health".to_owned(),
                mcp_path: "mcp".to_owned(),
                allowed_origins: Vec::new(),
                replay_window_limit: 16,
                session_idle_timeout_ms: 900_000,
                shutdown_timeout_ms: 30_000,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_allowed_origin() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "/health".to_owned(),
                mcp_path: "/mcp".to_owned(),
                allowed_origins: vec![String::new()],
                replay_window_limit: 16,
                session_idle_timeout_ms: 900_000,
                shutdown_timeout_ms: 30_000,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_zero_replay_window_limit() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "/health".to_owned(),
                mcp_path: "/mcp".to_owned(),
                allowed_origins: Vec::new(),
                replay_window_limit: 0,
                session_idle_timeout_ms: 900_000,
                shutdown_timeout_ms: 30_000,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_zero_session_idle_timeout() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig {
                bind_address: "127.0.0.1:8787".to_owned(),
                health_path: "/health".to_owned(),
                mcp_path: "/mcp".to_owned(),
                allowed_origins: Vec::new(),
                replay_window_limit: 16,
                session_idle_timeout_ms: 0,
                shutdown_timeout_ms: 30_000,
                request_timeout_ms: 30_000,
                completion_rate_limit_per_sec: None,
                anonymous_rate_limit_per_min: 0, // tests opt out of the anon limiter unless exercising it
                anonymous_rate_limit_burst: 0,
                trust_proxy_ip: false,
                trust_subject_header: false,
                revalidate_mutated_tool_arguments: false,
                relax_request_id_uniqueness: false,
                unary_json_fast_path: false,
                access_log: true,
                enforce_modern_request_meta: false,
                scrub_process_env_after_boot: false,
                server_ping_interval_ms: None,
                max_sessions_per_tenant: 0,
                extra_resource_uri_schemes: Vec::new(),
                max_request_body_mb: 4,
                tls: None,
                tunnel: None,
                tunnel_federation: None,
                transport: TransportMode::Http,
                transports: Vec::new(),
                allow_private_backends: false,
                health_check: crate::config::HealthCheckConfig::default(),
            },
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_tool_access_rule_name() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfig {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: None,
                    rules: vec![ToolTrustRuleConfig {
                        tool_name: String::new(),
                        minimum_trust: TrustLevelConfig::HeaderAsserted,
                        cel_allow_if: None,
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

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_duplicate_tool_access_rule_names() {
    let config = AppConfig {
        storage: StorageConfig::default(),
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfig {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: None,
                    rules: vec![
                        ToolTrustRuleConfig {
                            tool_name: "mcpg.runtime.snapshot".to_owned(),
                            minimum_trust: TrustLevelConfig::HeaderAsserted,
                            cel_allow_if: None,
                            required_scopes: Vec::new(),
                        },
                        ToolTrustRuleConfig {
                            tool_name: "mcpg.runtime.snapshot".to_owned(),
                            minimum_trust: TrustLevelConfig::Unauthenticated,
                            cel_allow_if: None,
                            required_scopes: Vec::new(),
                        },
                    ],
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_tool_access_cel_expression() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfig {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: Some("   ".to_owned()),
                    rules: Vec::new(),
                },
                cache: PolicyCacheConfig::default(),
                engine: Vec::new(),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_tool_rule_cel_expression() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig::default(),
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig {
                tool_access: ToolAccessPolicyConfig {
                    default_minimum_trust: TrustLevelConfig::HeaderAsserted,
                    cel_allow_if: None,
                    rules: vec![ToolTrustRuleConfig {
                        tool_name: "mcpg.runtime.snapshot".to_owned(),
                        minimum_trust: TrustLevelConfig::HeaderAsserted,
                        cel_allow_if: Some("  ".to_owned()),
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

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_logging_outputs() {
    let config = AppConfig {
        gateway: GatewayConfig {
            server: ServerConfig::default(),
            ..Default::default()
        },
        observability: ObservabilityConfig {
            logs: LogsConfig {
                enabled: true,
                level: "info".to_owned(),
                sinks: Vec::new(),
            },
            ..ObservabilityConfig::default()
        },
        governance: GovernanceConfig {
            policy: PolicyConfig::default(),
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_debug_network_header_with_newline_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    DebugCommandToolConfig::default(),
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig {
                        headers: std::collections::BTreeMap::from([(
                            "Authorization".to_owned(),
                            "Bearer test\nvalue".to_owned(),
                        )]),
                        ..DebugNetworkToolConfig::default()
                    },
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_zero_debug_command_timeout_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    DebugCommandToolConfig {
                        timeout_ms: 0,
                        ..DebugCommandToolConfig::default()
                    },
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig::default(),
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_zero_debug_network_max_response_bytes_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    DebugCommandToolConfig::default(),
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig {
                        max_response_bytes: 0,
                        ..DebugNetworkToolConfig::default()
                    },
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_debug_network_expected_status_codes_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    DebugCommandToolConfig::default(),
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig {
                        expected_status_codes: Vec::new(),
                        ..DebugNetworkToolConfig::default()
                    },
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_invalid_debug_network_expected_status_code_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_COMMAND_PROFILE.to_owned(),
                    DebugCommandToolConfig::default(),
                )]),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig {
                        expected_status_codes: vec![0],
                        ..DebugNetworkToolConfig::default()
                    },
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_missing_default_command_profile_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                command_profiles: std::collections::BTreeMap::new(),
                network_profiles: std::collections::BTreeMap::from([(
                    DEFAULT_NETWORK_PROFILE.to_owned(),
                    DebugNetworkToolConfig::default(),
                )]),
                bindings: DebugToolBackendsConfig::default(),
                exposure: DebugToolExposureConfig::default(),
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_missing_bound_command_profile_when_debug_enabled() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                bindings: DebugToolBackendsConfig {
                    command_probe_profile: "missing-command-profile".to_owned(),
                    network_probe_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
                    network_json_call_profile: DEFAULT_NETWORK_PROFILE.to_owned(),
                },
                ..DebugToolsConfig::default()
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_when_all_debug_tools_are_hidden() {
    let config = AppConfig {
        debug: DebugConfig {
            tools: DebugToolsConfig {
                exposure: DebugToolExposureConfig {
                    command_probe: false,
                    network_probe: false,
                    network_json_call: false,
                    operational_overview_prompt: false,
                    runtime_overview_resource: false,
                },
                ..DebugToolsConfig::default()
            },
        },
        feature_flags: FeatureFlagsConfig {
            debug_tools_enabled: true,
            ..Default::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_backend_name() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: String::new(),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn validate_rejects_empty_backend_description() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
                    title: None,
                    description: "   ".to_owned(),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };

    assert!(config.validate().is_err());
}

fn config_with_sessions_store(over: StoreOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                sessions: SessionsConfig {
                    store: Some(over),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

fn config_with_pipelines_store(over: StoreOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                pipelines: PipelinesConfig { store: Some(over) },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

fn config_with_subscriptions_store(over: StoreOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                subscriptions: SubscriptionsConfig {
                    store: Some(over),
                    max_per_session: 100,
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

fn config_with_delivery_bus(over: BusOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                delivery: DeliveryConfig { bus: Some(over) },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

fn config_with_cancellation_bus(over: BusOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                cancellation: CancellationConfig {
                    bus: Some(over),
                    partition_by_principal: false,
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

fn config_with_tasks_store(over: StoreOverrideConfig) -> AppConfig {
    AppConfig {
        mcp: McpConfig {
            capabilities: McpCapabilitiesConfig {
                tasks: TasksConfig {
                    store: Some(over),
                    ..TasksConfig::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

#[test]
fn validate_session_store_override_accepts_memory_kind() {
    // Only the override field is on `SessionsConfig`.
    let config = config_with_sessions_store(StoreOverrideConfig {
        kind: "memory".to_owned(),
        config: Default::default(),
    });
    assert!(config.validate().is_ok());
}

#[test]
fn validate_session_store_override_rejects_unloaded_plugin_alias() {
    // A short-alias whose expanded plugin id is not in the loaded
    // `plugins[]` list is rejected at config-validate time, so
    // operators get the typo with a path-qualified error before any
    // plugin loading begins.
    let config = config_with_sessions_store(StoreOverrideConfig {
        kind: "postgres".to_owned(),
        config: Default::default(),
    });
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("mcp.configurations.sessions.store.kind"),
        "expected path-qualified error, got: {err}"
    );
    assert!(
        err.contains("dev.mcpg.kv.postgres"),
        "expected expanded plugin id in error, got: {err}"
    );
}

// NOTE: a positive test for "short-alias resolves to a loaded
// KV plugin" can't be added today — `validate_plugins` only
// accepts `tool-gate | transform | identity` for the YAML
// `class:` field, so a `class: kv` entry fails an earlier
// validator before resolve_kind sees it.

#[test]
fn validate_session_store_override_rejects_empty_kind() {
    let config = config_with_sessions_store(StoreOverrideConfig {
        kind: String::new(),
        config: Default::default(),
    });
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("must not be empty"), "{err}");
}

#[test]
fn validate_pipeline_store_override_accepts_memory_kind() {
    let config = config_with_pipelines_store(StoreOverrideConfig {
        kind: "memory".to_owned(),
        config: Default::default(),
    });
    assert!(config.validate().is_ok());
}

#[test]
fn validate_task_store_override_accepts_memory_kind() {
    let config = config_with_tasks_store(StoreOverrideConfig {
        kind: "memory".to_owned(),
        config: Default::default(),
    });
    assert!(config.validate().is_ok(), "override wins for task_store");
}

#[test]
fn validate_subscription_store_override_accepts_memory_kind() {
    let config = config_with_subscriptions_store(StoreOverrideConfig {
        kind: "memory".to_owned(),
        config: Default::default(),
    });
    assert!(
        config.validate().is_ok(),
        "override wins for subscription_store"
    );
}

#[test]
fn validate_delivery_bus_override_accepts_memory_kind() {
    let config = config_with_delivery_bus(BusOverrideConfig {
        kind: "memory".to_owned(),
        config: Default::default(),
    });
    assert!(config.validate().is_ok());
}

#[test]
fn validate_cancellation_bus_override_rejects_unknown_kind() {
    let config = config_with_cancellation_bus(BusOverrideConfig {
        kind: "kafka".to_owned(),
        config: Default::default(),
    });
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("kafka") || err.contains("not recognised"),
        "{err}"
    );
}

// ----- cancellation principal-partitioning boot guard -----

/// Build an AppConfig with `cancellation.partition_by_principal = true`,
/// a given `cluster.kind`, and an optional `cancellation.bus` override.
fn config_with_cancellation_partitioning(
    cluster_kind: &str,
    bus: Option<BusOverrideConfig>,
) -> AppConfig {
    AppConfig {
        cluster: ClusterConfig {
            kind: cluster_kind.to_owned(),
            ..ClusterConfig::default()
        },
        mcp: McpConfig {
            configurations: McpConfigurationsConfig {
                cancellation: CancellationConfig {
                    bus,
                    partition_by_principal: true,
                },
                ..Default::default()
            },
            ..Default::default()
        },
        ..AppConfig::default()
    }
}

#[test]
fn cancellation_partitioning_disabled_is_always_ok() {
    // Default (flag off) is single-node safe regardless of backend.
    let config = AppConfig::default();
    assert!(config.validate_cancellation_partitioning().is_ok());
}

#[test]
fn cancellation_partitioning_rejected_on_single_node() {
    // single_node's in-process bus is exact-match; a `mcpg.cancel.*`
    // wildcard subscribe would match nothing and silently drop cancels.
    let config = config_with_cancellation_partitioning("single_node", None);
    let err = config
        .validate_cancellation_partitioning()
        .expect_err("partitioning on single_node must be refused");
    let msg = err.to_string();
    assert!(msg.contains("wildcard-capable"), "{msg}");
    assert!(msg.contains("single_node"), "{msg}");
}

#[test]
fn cancellation_partitioning_rejected_on_memory_bus_override() {
    // A `memory` bus override pins the exact-match in-process bus even
    // when cluster.kind would otherwise be wildcard-capable.
    let config = config_with_cancellation_partitioning(
        "redis",
        Some(BusOverrideConfig {
            kind: "memory".to_owned(),
            config: Default::default(),
        }),
    );
    let err = config
        .validate_cancellation_partitioning()
        .expect_err("memory override must be refused even under redis cluster");
    assert!(err.to_string().contains("memory"), "{err}");
}

#[test]
fn cancellation_partitioning_accepted_on_redis_and_nats() {
    // redis (PSUBSCRIBE) and nats (subject wildcards) are wildcard-capable.
    for kind in ["redis", "nats"] {
        let config = config_with_cancellation_partitioning(kind, None);
        assert!(
            config.validate_cancellation_partitioning().is_ok(),
            "{kind} should accept principal partitioning"
        );
    }
}

#[test]
fn cancellation_partitioning_accepted_with_cluster_meta_override_on_nats() {
    // A `cluster` bus override delegates to the coordinator, so it inherits
    // the (wildcard-capable) cluster.kind.
    let config = config_with_cancellation_partitioning(
        "nats",
        Some(BusOverrideConfig {
            kind: crate::config::store_override::CLUSTER_KIND.to_owned(),
            config: Default::default(),
        }),
    );
    assert!(config.validate_cancellation_partitioning().is_ok());
}

// ----- validate_wiring_resolution coverage -----

#[test]
fn validate_policy_engine_rejects_unloaded_plugin_id() {
    // Every entry in `governance.policy.engine[]` resolves through
    // `resolve_kind` at config-validate time. A reverse-domain id
    // that names a non-loaded plugin fails with a path-qualified
    // error.
    let mut config = AppConfig::default();
    config.governance.policy.engine = vec![
        crate::config::wiring::KindRef {
            kind: "yaml-rules".to_owned(),
            config: serde_json::Value::Null,
        },
        crate::config::wiring::KindRef {
            kind: "dev.acme.policy.unknown".to_owned(),
            config: serde_json::Value::Null,
        },
    ];
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("governance.policy.engine[1]"),
        "expected indexed path, got: {err}"
    );
    assert!(
        err.contains("dev.acme.policy.unknown"),
        "expected plugin id in error, got: {err}"
    );
}

#[test]
fn validate_quotas_store_rejects_unloaded_plugin_alias() {
    // `governance.quotas.store.kind` resolves via SlotClass::Kv. A
    // short-alias whose expanded id doesn't match any loaded plugin
    // fails at validate time.
    let mut config = AppConfig::default();
    config.governance.quotas.store = crate::config::wiring::KindRef {
        kind: "redis-cluster".to_owned(),
        config: serde_json::Value::Null,
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("governance.quotas.store.kind"),
        "expected path-qualified error, got: {err}"
    );
}

#[test]
fn validate_quotas_store_accepts_cluster_meta_kind() {
    // The default `kind: cluster` always resolves cleanly
    // when the cluster coordinator provides the kv role —
    // single_node coordinator does, so this is the default
    // shape.
    let mut config = AppConfig::default();
    config.governance.quotas.store = crate::config::wiring::KindRef {
        kind: "cluster".to_owned(),
        config: serde_json::Value::Null,
    };
    config.validate().expect("kind: cluster default validates");
}

#[test]
fn validate_per_binding_cache_rejects_unloaded_plugin_alias() {
    // Each binding's `cache.kind` resolves via SlotClass::Cache at
    // validate time.
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
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
                    governance: BackendGovernanceConfig::default(),
                    retry: None,
                    content_storage: None,
                    cache: Some(crate::config::wiring::KindRef {
                        kind: "redis".to_owned(),
                        config: serde_json::Value::Null,
                    }),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("mcp.capabilities.tools[name=`test.tool`].cache.kind"),
        "expected path-qualified error, got: {err}"
    );
}

#[test]
fn validate_per_binding_cache_accepts_disabled_keyword() {
    // The Cache slot has a special `disabled` keyword for
    // explicit per-binding cache opt-out (lives in
    // `is_builtin_keyword`). It must pass validate.
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
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
                    governance: BackendGovernanceConfig::default(),
                    retry: None,
                    content_storage: None,
                    cache: Some(crate::config::wiring::KindRef {
                        kind: "disabled".to_owned(),
                        config: serde_json::Value::Null,
                    }),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    config
        .validate()
        .expect("`disabled` keyword passes Cache slot");
}

// --- Metrics config validation ---
//
// Prometheus opt-in is the `dev.mcpg.observability.prometheus`
// plugin id. The gateway's MetricsConfig validator only checks
// that `kind` is non-empty; per-kind validation lives in each
// plugin's `from_config_json` (with `serde(deny_unknown_
// fields)` for early typo detection).

#[test]
fn validate_metrics_config_accepts_default() {
    let config = AppConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_metrics_config_accepts_plugin_id_kinds() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            metrics: MetricsConfig {
                enabled: true,
                sinks: vec![SinkConfig {
                    kind: "dev.mcpg.observability.prometheus".to_owned(),
                    config: serde_json::json!({}),
                    level: None,
                }],
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_metrics_config_rejects_empty_kind() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            metrics: MetricsConfig {
                enabled: true,
                sinks: vec![SinkConfig {
                    kind: "".to_owned(),
                    config: serde_json::json!({}),
                    level: None,
                }],
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("kind must not be empty"));
}

// --- Traces config validation ---

#[test]
fn validate_traces_config_rejects_enabled_without_sinks() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            traces: TracesConfig {
                enabled: true,
                sinks: Vec::new(),
                ..TracesConfig::default()
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("observability.traces.sinks must not be empty")
    );
}

#[test]
fn validate_traces_config_rejects_empty_service_name() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            traces: TracesConfig {
                enabled: true,
                service_name: "  ".to_owned(),
                sinks: vec![SinkConfig {
                    kind: "otlp".to_owned(),
                    config: serde_json::json!({"url": "http://localhost:4317"}),
                    level: None,
                }],
                propagate_context: true,
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("observability.traces.service_name must not be empty")
    );
}

#[test]
fn validate_traces_config_disabled_skips_validation() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            traces: TracesConfig {
                enabled: false,
                service_name: "mcpg".to_owned(),
                sinks: Vec::new(),
                propagate_context: true,
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_traces_config_accepts_otlp_sink() {
    let config = AppConfig {
        observability: ObservabilityConfig {
            traces: TracesConfig {
                enabled: true,
                sinks: vec![SinkConfig {
                    kind: "otlp".to_owned(),
                    config: serde_json::json!({"url": "http://localhost:4317"}),
                    level: None,
                }],
                ..TracesConfig::default()
            },
            ..ObservabilityConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_non_object_input_schema() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
                    title: None,
                    description: "test".to_owned(),
                    input_schema: Some(serde_json::json!("not an object")),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("input_schema must be a JSON object"));
}

#[test]
fn validate_rejects_invalid_json_schema() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
                    title: None,
                    description: "test".to_owned(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "not_a_valid_type" }
                        }
                    })),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("not a valid JSON Schema"));
}

#[test]
fn validate_accepts_valid_input_schema() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
                    title: None,
                    description: "test".to_owned(),
                    input_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" },
                            "limit": { "type": "integer", "minimum": 1 }
                        },
                        "required": ["query"]
                    })),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_whitespace_only_binding_title() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "test.tool".to_owned(),
                    title: Some("   ".to_owned()),
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
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("title must not be whitespace-only"));
}

#[test]
fn validate_accepts_valid_jwks_auth_config() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "https://auth.example.com/.well-known/jwks.json".to_owned(),
                    keys_json: None,
                    issuer: Some("https://auth.example.com/".to_owned()),
                    audience: Some("mcpg".to_owned()),
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_minimal_jwks_auth_config() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "http://localhost:8080/.well-known/jwks.json".to_owned(),
                    keys_json: None,
                    issuer: None,
                    audience: None,
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_jwks_without_url_or_keys() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "".to_owned(),
                    keys_json: None,
                    issuer: None,
                    audience: None,
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("must have either"));
}

#[test]
fn validate_rejects_non_http_jwks_url() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "ftp://example.com/jwks".to_owned(),
                    keys_json: None,
                    issuer: None,
                    audience: None,
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("governance.access.jwks.url must start with http:// or https://"));
}

#[test]
fn validate_rejects_whitespace_only_jwks_issuer() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "https://auth.example.com/jwks".to_owned(),
                    keys_json: None,
                    issuer: Some("   ".to_owned()),
                    audience: None,
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("governance.access.jwks.issuer must not be empty when provided"));
}

#[test]
fn validate_rejects_empty_jwks_header_name() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "https://auth.example.com/jwks".to_owned(),
                    keys_json: None,
                    issuer: None,
                    audience: None,
                    header_name: "  ".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("governance.access.jwks.header_name must not be empty"));
}

#[test]
fn validate_accepts_jwks_with_inline_keys_json() {
    let config = AppConfig {
        governance: GovernanceConfig {
            access: AccessConfig {
                authorization_server: None,
                oidc_oauth: None,
                resource_metadata: None,
                jwks: Some(JwksConfig {
                    url: "".to_owned(),
                    keys_json: Some(r#"{"keys":[]}"#.to_owned()),
                    issuer: None,
                    audience: None,
                    header_name: "authorization".to_owned(),
                    header_prefix: "Bearer ".to_owned(),
                    allow_missing_audience: true,
                }),
            },
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn trust_level_config_verified_orders_above_header_asserted() {
    assert!(TrustLevelConfig::Verified > TrustLevelConfig::HeaderAsserted);
    assert!(TrustLevelConfig::HeaderAsserted > TrustLevelConfig::Unauthenticated);
    assert!(TrustLevelConfig::Verified > TrustLevelConfig::Unauthenticated);
}

// --- OAuth Protected Resource Metadata config tests ---

#[test]
fn validate_accepts_valid_resource_metadata() {
    let rm = OAuthResourceMetadataConfig {
        resource: "https://gateway.example.com/mcp".to_owned(),
        authorization_servers: vec!["https://auth.example.com/".to_owned()],
        scopes_supported: vec![],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    };
    assert!(rm.validate().is_ok());
}

#[test]
fn validate_rejects_empty_resource_metadata_resource() {
    let rm = OAuthResourceMetadataConfig {
        resource: "".to_owned(),
        authorization_servers: vec![],
        scopes_supported: vec![],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    };
    let err = rm.validate().unwrap_err().to_string();
    assert!(err.contains("resource must not be empty"));
}

#[test]
fn validate_rejects_non_url_resource_metadata_resource() {
    let rm = OAuthResourceMetadataConfig {
        resource: "not-a-url".to_owned(),
        authorization_servers: vec![],
        scopes_supported: vec![],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: false,
    };
    let err = rm.validate().unwrap_err().to_string();
    assert!(err.contains("valid absolute URL"));
}

#[test]
fn resource_metadata_default_bearer_methods() {
    let json = r#"{"resource": "https://example.com/mcp"}"#;
    let rm: OAuthResourceMetadataConfig = serde_json::from_str(json).unwrap();
    assert_eq!(rm.bearer_methods_supported, vec!["header"]);
}

fn prm_with_resource(resource: &str, allow_loopback: bool) -> OAuthResourceMetadataConfig {
    OAuthResourceMetadataConfig {
        resource: resource.to_owned(),
        authorization_servers: vec![],
        scopes_supported: vec![],
        bearer_methods_supported: vec!["header".to_owned()],
        allow_loopback_resource: allow_loopback,
    }
}

/// TAN-05 (RFC 8707/9728): a wildcard/unspecified bind host is never a
/// valid token audience and is refused even with the loopback opt-in.
#[test]
fn validate_rejects_wildcard_resource() {
    let err = prm_with_resource("http://0.0.0.0:8080/mcp", true)
        .validate()
        .unwrap_err()
        .to_string();
    assert!(err.contains("wildcard"), "got: {err}");
    let err6 = prm_with_resource("http://[::]:8080/mcp", true)
        .validate()
        .unwrap_err()
        .to_string();
    assert!(err6.contains("wildcard"), "got: {err6}");
}

/// TAN-05: a loopback resource is refused unless the dev opt-in is set.
#[test]
fn validate_rejects_loopback_resource_without_opt_in() {
    for host in [
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
    ] {
        let err = prm_with_resource(host, false)
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("loopback"), "host {host} got: {err}");
        // With the opt-in it validates (local dev).
        assert!(
            prm_with_resource(host, true).validate().is_ok(),
            "host {host} should pass with allow_loopback_resource"
        );
    }
}

/// TAN-05: RFC 8707 §2 — the resource identifier MUST NOT carry a fragment.
#[test]
fn validate_rejects_resource_with_fragment() {
    let err = prm_with_resource("https://gateway.example.com/mcp#frag", false)
        .validate()
        .unwrap_err()
        .to_string();
    assert!(err.contains("fragment"), "got: {err}");
}

/// AUTH-02/AUTH-10 (RFC 9728 §3.1): the well-known metadata URL is the
/// path-aware form — the suffix is inserted between host and path.
#[test]
fn well_known_url_is_path_aware_and_absolute() {
    let rm = prm_with_resource("https://gateway.example.com/mcp", false);
    assert_eq!(
        rm.well_known_url(),
        "https://gateway.example.com/.well-known/oauth-protected-resource/mcp"
    );
    // No path → root suffix.
    let root = prm_with_resource("https://gateway.example.com", false);
    assert_eq!(
        root.well_known_url(),
        "https://gateway.example.com/.well-known/oauth-protected-resource"
    );
    // Trailing slash on the host is stripped before the suffix.
    let slash = prm_with_resource("https://gateway.example.com/", false);
    assert_eq!(
        slash.well_known_url(),
        "https://gateway.example.com/.well-known/oauth-protected-resource"
    );
    // Port is preserved on the authority.
    let ported = prm_with_resource("https://gateway.example.com:8443/mcp", false);
    assert_eq!(
        ported.well_known_url(),
        "https://gateway.example.com:8443/.well-known/oauth-protected-resource/mcp"
    );
}

// --- Canonical SHA-256 ---

#[test]
fn canonical_sha256_default_is_64_hex_chars() {
    let sha = AppConfig::default().canonical_sha256();
    assert_eq!(sha.len(), 64);
    assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn canonical_sha256_stable_across_calls() {
    let cfg = AppConfig::default();
    assert_eq!(cfg.canonical_sha256(), cfg.canonical_sha256());
}

#[test]
fn canonical_sha256_changes_when_config_changes() {
    let baseline = AppConfig::default();
    let mut tweaked = AppConfig::default();
    tweaked.gateway.server.replay_window_limit = baseline.gateway.server.replay_window_limit + 1;
    assert_ne!(baseline.canonical_sha256(), tweaked.canonical_sha256());
}

#[test]
fn canonical_sha256_invariant_to_yaml_key_ordering() {
    // Two YAML strings whose top-level keys differ only in order
    // should hash to the same digest.
    let yaml_a = "gateway:\n  server:\n    bind_address: \"127.0.0.1:8787\"\ngovernance: {}\n";
    let yaml_b = "governance: {}\ngateway:\n  server:\n    bind_address: \"127.0.0.1:8787\"\n";
    let cfg_a = AppConfig::load_from_yaml_str(yaml_a).expect("parse A");
    let cfg_b = AppConfig::load_from_yaml_str(yaml_b).expect("parse B");
    assert_eq!(cfg_a.canonical_sha256(), cfg_b.canonical_sha256());
}

#[test]
fn canonicalize_json_sorts_object_keys_recursively() {
    let input = serde_json::json!({
        "z": {"y": 1, "a": 2},
        "a": [{"second": 2, "first": 1}, "scalar"],
    });
    let canon = canonicalize_json(&input);
    let serialised = serde_json::to_string(&canon).unwrap();
    // Top-level keys sorted alphabetically:
    assert!(serialised.starts_with("{\"a\":"), "{serialised}");
    // Nested object keys sorted; array order preserved.
    assert!(
        serialised.contains("[{\"first\":1,\"second\":2},\"scalar\"]"),
        "{serialised}",
    );
    assert!(
        serialised.contains("\"z\":{\"a\":2,\"y\":1}"),
        "{serialised}"
    );
}

// --- Features config tests ---

#[test]
fn features_config_defaults_off() {
    let cfg = FeatureFlagsConfig::default();
    assert!(!cfg.allow_header_passthrough);
    assert!(!cfg.sep2260_panic_on_orphan);
    assert!(!cfg.any_active());
    assert_eq!(cfg.audit_details(), serde_json::json!({}));
}

#[test]
fn features_config_audit_details_omits_default_flags() {
    let cfg = FeatureFlagsConfig {
        allow_header_passthrough: true,
        sep2260_panic_on_orphan: false,
        debug_tools_enabled: false,
    };
    assert!(cfg.any_active());
    assert_eq!(
        cfg.audit_details(),
        serde_json::json!({"allow_header_passthrough": true}),
    );
}

#[test]
fn features_config_yaml_round_trip() {
    let yaml = "allow_header_passthrough: true\nsep2260_panic_on_orphan: true\n";
    let cfg: FeatureFlagsConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.allow_header_passthrough);
    assert!(cfg.sep2260_panic_on_orphan);
    assert!(cfg.any_active());
}

#[test]
fn features_config_validate_accepts_default() {
    let cfg = AppConfig {
        feature_flags: FeatureFlagsConfig::default(),
        ..AppConfig::default()
    };
    assert!(cfg.validate().is_ok());
}

// NATS connection params live on NatsBackendConfig directly;
// URL/credentials validation is exercised by
// `NatsBackendConfig::validate` and the per-binding tests below.

#[test]
fn tls_config_accepts_server_only_no_client_auth() {
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.2".into(),
        client_ca_certs_path: None,
        client_cert_required: ClientCertMode::None,
    };
    cfg.validate().unwrap();
}

#[test]
fn tls_config_accepts_mandatory_mtls_with_ca() {
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.3".into(),
        client_ca_certs_path: Some("/etc/mcpg/client-ca.pem".into()),
        client_cert_required: ClientCertMode::Mandatory,
    };
    cfg.validate().unwrap();
}

#[test]
fn tls_config_accepts_optional_mtls_with_ca() {
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.2".into(),
        client_ca_certs_path: Some("/etc/mcpg/client-ca.pem".into()),
        client_cert_required: ClientCertMode::Optional,
    };
    cfg.validate().unwrap();
}

#[test]
fn tls_config_rejects_mtls_without_ca_path() {
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.2".into(),
        client_ca_certs_path: None,
        client_cert_required: ClientCertMode::Mandatory,
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("client_ca_certs_path"), "got: {err}");
}

#[test]
fn tls_config_rejects_ca_path_without_mtls_mode() {
    // Operator setting CA path with mode=none is almost
    // certainly a typo — easier to surface at boot than wonder
    // why the gateway doesn't ask for client certs.
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.2".into(),
        client_ca_certs_path: Some("/etc/mcpg/client-ca.pem".into()),
        client_cert_required: ClientCertMode::None,
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("client_ca_certs_path"), "got: {err}");
}

#[test]
fn tls_config_rejects_empty_ca_path_in_mtls_mode() {
    let cfg = TlsConfig {
        cert_path: "/etc/mcpg/tls.crt".into(),
        key_path: "/etc/mcpg/tls.key".into(),
        min_tls_version: "1.2".into(),
        client_ca_certs_path: Some("   ".into()),
        client_cert_required: ClientCertMode::Optional,
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("client_ca_certs_path"), "got: {err}");
}

#[test]
fn client_cert_mode_default_is_none() {
    assert_eq!(ClientCertMode::default(), ClientCertMode::None);
    assert!(!ClientCertMode::None.requires_ca());
    assert!(ClientCertMode::Optional.requires_ca());
    assert!(ClientCertMode::Mandatory.requires_ca());
}

#[test]
fn tls_config_default_serde_roundtrip_keeps_no_client_auth() {
    // Pre-existing TLS configs (just cert + key, no client cert
    // fields) MUST keep working — `client_cert_required`
    // defaults to None and `client_ca_certs_path` defaults to
    // absent.
    let yaml = r#"
            cert_path: /etc/mcpg/tls.crt
            key_path: /etc/mcpg/tls.key
        "#;
    let cfg: TlsConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.client_cert_required, ClientCertMode::None);
    assert!(cfg.client_ca_certs_path.is_none());
    assert_eq!(cfg.min_tls_version, "1.2");
    cfg.validate().unwrap();
}

fn sample_nats_binding_with_subject(subject: &str) -> NatsBackendConfig {
    NatsBackendConfig {
        url: "nats://localhost:4222".to_owned(),
        credentials_path: None,
        subject: subject.to_owned(),
        timeout_ms: 2000,
        max_response_bytes: 65536,
    }
}

#[test]
fn nats_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "nats-tool".to_owned(),
                    title: None,
                    description: "A NATS-backed tool".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed(
                        "nats",
                        sample_nats_binding_with_subject("mcpg.exec.request.tools.test"),
                    ),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

// --- gRPC binding config tests ---

// --- GraphQL binding config tests ---

// --- Kafka binding config tests ---

fn sample_kafka_binding() -> KafkaBackendConfig {
    KafkaBackendConfig {
        bootstrap_servers: "localhost:9092".to_owned(),
        group_id: "mcpg".to_owned(),
        request_topic: "my-requests".to_owned(),
        response_topic: "my-responses".to_owned(),
        timeout_ms: 10000,
        max_response_bytes: 65536,
    }
}

// --- Cross-validation tests ---

#[test]
fn kafka_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "kafka-tool".to_owned(),
                    title: None,
                    description: "A Kafka-backed tool".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed("kafka", sample_kafka_binding()),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn grpc_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "grpc-tool".to_owned(),
                    title: None,
                    description: "A gRPC-backed tool".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed(
                        "grpc",
                        serde_json::json!({
                            "url": "http://localhost:50051",
                            "service": "mypackage.MyService",
                            "method": "MyMethod",
                            "timeout_ms": 5000,
                            "max_response_bytes": 65536,
                            "headers": {},
                        }),
                    ),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn graphql_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "graphql-tool".to_owned(),
                    title: None,
                    description: "A GraphQL-backed tool".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed(
                        "graphql",
                        serde_json::json!({
                            "url": "http://localhost:4000/graphql",
                            "operation": "query { users { name } }",
                            "timeout_ms": 5000,
                            "max_response_bytes": 65536,
                            "headers": {},
                        }),
                    ),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

// --- Mock binding config tests ---

#[test]
fn mock_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "mock-tool".to_owned(),
                    title: None,
                    description: "A mock-backed tool".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed(
                        "mock",
                        MockBackendConfig {
                            response: serde_json::json!({"hello": "world"}),
                            delay_ms: 0,
                            error: false,
                            error_message: None,
                            passthrough: false,
                        },
                    ),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

// --- Pipeline binding config tests ---

fn sample_mock_step(id: &str) -> PipelineStepConfig {
    PipelineStepConfig::backend_from_typed(
        id.to_owned(),
        "mock",
        MockBackendConfig {
            response: serde_json::json!({"step": id}),
            delay_ms: 0,
            error: false,
            error_message: None,
            passthrough: false,
        },
        None,
    )
}

#[test]
fn pipeline_binding_validates_in_app_config() {
    let config = AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![BackendConfig {
                    name: "my_pipeline".to_owned(),
                    title: None,
                    description: "A multi-step pipeline".to_owned(),
                    input_schema: None,
                    backend: BackendImpl::from_typed(
                        "pipeline",
                        PipelineBackendConfig {
                            pipeline_timeout_ms: 10000,
                            steps: vec![
                                sample_mock_step("fetch"),
                                PipelineStepConfig::Transform(PipelineTransformStepConfig {
                                    id: "reshape".to_owned(),
                                    expression: "steps.fetch.output".to_owned(),
                                }),
                                PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
                                    id: "check".to_owned(),
                                    expression: "steps.fetch.output.step == \"fetch\"".to_owned(),
                                    error_message: None,
                                }),
                            ],
                        },
                    ),
                    governance: BackendGovernanceConfig::default(),
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
                }],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn pipeline_step_config_type_label() {
    assert_eq!(sample_mock_step("s").type_label(), "mock");
    assert_eq!(
        PipelineStepConfig::Transform(PipelineTransformStepConfig {
            id: "t".to_owned(),
            expression: "args".to_owned(),
        })
        .type_label(),
        "transform"
    );
    assert_eq!(
        PipelineStepConfig::CelGate(PipelineCelGateStepConfig {
            id: "g".to_owned(),
            expression: "true".to_owned(),
            error_message: None,
        })
        .type_label(),
        "cel_gate"
    );
}

#[test]
fn pipeline_step_config_id_accessor() {
    let step = sample_mock_step("my_step");
    assert_eq!(step.id(), "my_step");
}

#[test]
fn pipeline_step_is_suspending_classification() {
    let elicit = PipelineStepConfig::Elicitation(PipelineElicitationStepConfig {
        id: "e".to_owned(),
        message: "hi".to_owned(),
        requested_schema: None,
        timeout_ms: 1000,
        mode: Default::default(),
        url: None,
        elicitation_id: None,
        presentation_hint: None,
        meta: None,
        correlation_token: None,
        skip_if_unsupported: false,
    });
    let sampling = PipelineStepConfig::Sampling(PipelineSamplingStepConfig {
        id: "s".to_owned(),
        messages: vec![SamplingMessageConfig {
            role: "user".to_owned(),
            content: "hi".to_owned(),
        }],
        max_tokens: 100,
        timeout_ms: 1000,
        system_prompt: None,
        include_context: None,
        temperature: None,
        stop_sequences: None,
        model_preferences: None,
        tools: None,
        tool_choice: None,
        meta: None,
        metadata: None,
        correlation_token: None,
        skip_if_unsupported: false,
    });
    let mock = PipelineStepConfig::backend_from_typed(
        "m".to_owned(),
        "mock",
        MockBackendConfig {
            response: serde_json::json!({}),
            delay_ms: 0,
            error: false,
            error_message: None,
            passthrough: false,
        },
        None,
    );
    assert!(elicit.is_suspending());
    assert!(sampling.is_suspending());
    assert!(!mock.is_suspending());
}

// --- Payment Config Tests ---

// -----------------------------------------------------------------------
// Plugins config tests
// -----------------------------------------------------------------------
//
// `plugins:` is a flat `Vec<PluginEntryConfig>`; the wiring fields
// (`kv`, `caches`, `secrets`, `configs`, `transports`, `policy`,
// `capability_grants`, `trust`, `credentials`, etc.) live elsewhere.

#[test]
fn audit_config_defaults_to_required_fail_closed() {
    // A bare `audit:` block with no overrides should deserialise to
    // the compliance-safe defaults.
    let cfg = AuditConfig::default();
    assert!(cfg.required, "required defaults to true");
    assert_eq!(cfg.on_failure, AuditOnFailure::FailClosed);
    assert_eq!(
        cfg.sinks.len(),
        1,
        "default ships the built-in local-file audit sink"
    );
    assert_eq!(cfg.sinks[0].kind, "dev.mcpg.builtin.audit.local-file");
}

#[test]
fn audit_config_parses_explicit_values() {
    // Top-level `audit:` block with a sinks list. Operators omit
    // the built-in id from `sinks` to disable it.
    let yaml = r#"
required: false
on_failure: fail_open
sinks:
  - kind: dev.acme.audit.cloudtrail
    config:
      arn: arn:aws:cloudtrail:us-east-1:123:trail/mcpg
"#;
    let cfg: AuditConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(!cfg.required);
    assert_eq!(cfg.on_failure, AuditOnFailure::FailOpen);
    assert_eq!(cfg.sinks.len(), 1);
    assert_eq!(cfg.sinks[0].kind, "dev.acme.audit.cloudtrail");
}

#[test]
fn audit_config_validates_required_with_empty_sinks() {
    let cfg = AuditConfig {
        enabled: true,
        required: true,
        sinks: Vec::new(),
        ..AuditConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("audit.sinks must not be empty"));
}

#[test]
fn audit_on_failure_serialises_snake_case() {
    assert_eq!(
        serde_json::to_string(&AuditOnFailure::FailClosed).unwrap(),
        "\"fail_closed\""
    );
    assert_eq!(
        serde_json::to_string(&AuditOnFailure::FailOpen).unwrap(),
        "\"fail_open\""
    );
}

#[test]
fn cluster_config_parses_kind_and_inline_config() {
    let yaml = r#"
cluster:
  kind: redis
  url: redis://example:6379
  key_prefix: "mcpg:cluster:"
  lease_ttl_ms: 30000
"#;
    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.cluster.kind, "redis");
    assert_eq!(
        cfg.cluster.plugin_id().as_deref(),
        Some("dev.mcpg.cluster.redis")
    );
    assert!(!cfg.cluster.is_single_node());
    assert_eq!(
        cfg.cluster.config.get("url").and_then(|v| v.as_str()),
        Some("redis://example:6379")
    );
    assert_eq!(
        cfg.cluster
            .config
            .get("lease_ttl_ms")
            .and_then(|v| v.as_u64()),
        Some(30000)
    );
}

#[test]
fn cluster_readiness_gate_parses_and_defaults_off() {
    use crate::config::ClusterReadinessGate;
    // Default (unset) → Off (fail-open, the historical behaviour).
    let default: AppConfig = serde_yaml::from_str("cluster:\n  kind: redis\n").expect("parse");
    assert_eq!(default.cluster.readiness_gate, ClusterReadinessGate::Off);
    // Explicit values parse (snake_case).
    for (yaml_val, want) in [
        ("off", ClusterReadinessGate::Off),
        ("degrade", ClusterReadinessGate::Degrade),
        ("fail", ClusterReadinessGate::Fail),
    ] {
        let cfg: AppConfig = serde_yaml::from_str(&format!(
            "cluster:\n  kind: redis\n  readiness_gate: {yaml_val}\n  url: rediss://r:6379\n"
        ))
        .expect("parse");
        assert_eq!(cfg.cluster.readiness_gate, want, "for {yaml_val}");
        // The named field stays OUT of the flattened plugin config map.
        assert!(!cfg.cluster.config.contains_key("readiness_gate"));
    }
}

#[test]
fn cluster_config_defaults_to_single_node() {
    // Omitting `cluster:` defaults to the in-process built-in.
    let yaml = "{}";
    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.cluster.is_single_node());
    assert_eq!(cfg.cluster.kind, "single_node");
    assert!(cfg.cluster.plugin_id().is_none());
}

#[test]
fn cluster_backend_plugin_id_maps_known_kinds() {
    for (kind, expected) in [
        ("etcd", "dev.mcpg.cluster.etcd"),
        ("consul", "dev.mcpg.cluster.consul"),
        ("nats", "dev.mcpg.cluster.nats"),
        ("redis", "dev.mcpg.cluster.redis"),
    ] {
        let cfg = ClusterConfig {
            kind: kind.to_owned(),
            allow_insecure_transport: false,
            allow_degraded_boot: false,
            readiness_gate: Default::default(),
            state_encryption_key_env: None,
            state_encryption_key_id: None,
            state_encryption_allow_plaintext_reads: false,
            tenant_segment: None,
            config: serde_json::Map::new(),
        };
        assert_eq!(cfg.plugin_id().as_deref(), Some(expected));
    }
}

#[test]
fn cluster_plugin_id_follows_kind_convention() {
    // The gateway is kind-agnostic: any non-single_node kind resolves to
    // `dev.mcpg.cluster.<kind>` by convention. An unknown kind is not rejected
    // here — it fails closed at load when no `plugins[]` entry matches.
    let cfg = ClusterConfig {
        kind: "no-such-coordinator".to_owned(),
        allow_insecure_transport: false,
        allow_degraded_boot: false,
        readiness_gate: Default::default(),
        state_encryption_key_env: None,
        state_encryption_key_id: None,
        state_encryption_allow_plaintext_reads: false,
        tenant_segment: None,
        config: serde_json::Map::new(),
    };
    assert_eq!(
        cfg.plugin_id().as_deref(),
        Some("dev.mcpg.cluster.no-such-coordinator")
    );
}

// The opt-in state-encryption fields are NAMED fields, so serde must
// route them to the struct, NOT absorb them into the flattened plugin
// `config` map (where they'd be forwarded to the coordinator plugin + a
// typo would be silently swallowed).
#[test]
fn state_encryption_fields_not_leaked_into_flatten_config() {
    let cfg: ClusterConfig = serde_json::from_value(serde_json::json!({
        "kind": "redis",
        "url": "rediss://r:6379",
        "state_encryption_key_env": "MCPG_CLUSTER_STATE_KEY",
        "state_encryption_key_id": "kid-q1",
    }))
    .unwrap();
    assert_eq!(
        cfg.state_encryption_key_env.as_deref(),
        Some("MCPG_CLUSTER_STATE_KEY")
    );
    assert_eq!(cfg.state_encryption_key_id.as_deref(), Some("kid-q1"));
    // The per-kind flatten map keeps `url` but NOT the named fields.
    assert!(cfg.config.contains_key("url"));
    assert!(!cfg.config.contains_key("state_encryption_key_env"));
    assert!(!cfg.config.contains_key("state_encryption_key_id"));
}

// tenant_segment is a NAMED field (not leaked into the flattened
// plugin config) and is validated as a single broker-safe token.
#[test]
fn tenant_segment_not_leaked_into_flatten_config() {
    let cfg: ClusterConfig = serde_json::from_value(serde_json::json!({
        "kind": "redis",
        "url": "rediss://r:6379",
        "tenant_segment": "acme",
    }))
    .unwrap();
    assert_eq!(cfg.tenant_segment.as_deref(), Some("acme"));
    assert!(cfg.config.contains_key("url"));
    assert!(!cfg.config.contains_key("tenant_segment"));
}

#[test]
fn validate_tenant_segment_accepts_token_rejects_reserved_chars() {
    let ok = |seg: &str| {
        let c = ClusterConfig {
            tenant_segment: Some(seg.to_owned()),
            ..Default::default()
        };
        c.validate_tenant_segment()
    };
    assert!(ok("acme").is_ok());
    assert!(ok("team-7_x").is_ok());
    for bad in ["", "a.b", "a/b", "a*", "a>b", "a:b", "a b"] {
        assert!(ok(bad).is_err(), "expected {bad:?} to be rejected");
    }
    // Unset is always Ok.
    assert!(ClusterConfig::default().validate_tenant_segment().is_ok());
}

// Secure-by-default transport guard. `validate_transport_security`
// refuses a plaintext non-`single_node` coordinator at boot unless the
// operator opts in via `cluster.allow_insecure_transport: true`.

/// Build a `ClusterConfig` from a `kind` + a JSON object literal for the
/// flattened per-kind `config` map.
fn cluster_cfg(kind: &str, allow_insecure: bool, config: serde_json::Value) -> ClusterConfig {
    let config = match config {
        serde_json::Value::Object(map) => map,
        serde_json::Value::Null => serde_json::Map::new(),
        other => panic!("cluster config must be a JSON object, got {other:?}"),
    };
    ClusterConfig {
        kind: kind.to_owned(),
        allow_insecure_transport: allow_insecure,
        allow_degraded_boot: false,
        readiness_gate: Default::default(),
        state_encryption_key_env: None,
        state_encryption_key_id: None,
        state_encryption_allow_plaintext_reads: false,
        tenant_segment: None,
        config,
    }
}

#[test]
fn transport_security_single_node_is_always_ok() {
    // single_node never touches a network transport.
    let cfg = cluster_cfg("single_node", false, serde_json::Value::Null);
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn transport_security_refuses_plaintext_redis() {
    let cfg = cluster_cfg(
        "redis",
        false,
        serde_json::json!({ "url": "redis://r:6379" }),
    );
    let err = cfg
        .validate_transport_security()
        .expect_err("plaintext redis:// must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("rediss://"),
        "should suggest the TLS scheme: {msg}"
    );
    // Error must NOT echo the URL (it can carry credentials).
    assert!(!msg.contains("r:6379"), "must not echo the url: {msg}");
}

#[test]
fn transport_security_accepts_rediss() {
    let cfg = cluster_cfg(
        "redis",
        false,
        serde_json::json!({ "url": "rediss://r:6379" }),
    );
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn transport_security_opt_out_permits_plaintext_redis() {
    // allow_insecure_transport: true is the explicit local/dev escape hatch.
    let cfg = cluster_cfg(
        "redis",
        true,
        serde_json::json!({ "url": "redis://r:6379" }),
    );
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn transport_security_refuses_plaintext_consul() {
    let cfg = cluster_cfg(
        "consul",
        false,
        serde_json::json!({ "address": "http://consul:8500" }),
    );
    let err = cfg
        .validate_transport_security()
        .expect_err("plaintext http:// consul must be refused");
    assert!(err.to_string().contains("https://"));
}

#[test]
fn transport_security_accepts_https_consul() {
    let cfg = cluster_cfg(
        "consul",
        false,
        serde_json::json!({ "address": "https://consul:8500" }),
    );
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn transport_security_refuses_any_plaintext_etcd_endpoint() {
    // A single plaintext endpoint in the list is enough to refuse.
    let cfg = cluster_cfg(
        "etcd",
        false,
        serde_json::json!({ "endpoints": ["https://e1:2379", "http://e2:2379"] }),
    );
    let err = cfg
        .validate_transport_security()
        .expect_err("any plaintext http:// etcd endpoint must be refused");
    assert!(err.to_string().contains("https://"));
}

#[test]
fn transport_security_refuses_scheme_less_etcd_endpoint() {
    // A scheme-less `host:port` endpoint connects plaintext in etcd-client
    // — it must be treated as plaintext, not silently allowed.
    let cfg = cluster_cfg(
        "etcd",
        false,
        serde_json::json!({ "endpoints": ["etcd-0:2379", "etcd-1:2379"] }),
    );
    let err = cfg
        .validate_transport_security()
        .expect_err("scheme-less etcd endpoints must be refused as plaintext");
    assert!(err.to_string().contains("https://"));
}

#[test]
fn transport_security_refuses_whitespace_prefixed_plaintext() {
    // The guard trims leading whitespace so it classifies identically to the
    // plugins — a `" http://…"` endpoint must not slip past.
    let cfg = cluster_cfg(
        "etcd",
        false,
        serde_json::json!({ "endpoints": [" http://e1:2379"] }),
    );
    assert!(
        cfg.validate_transport_security().is_err(),
        "leading-whitespace plaintext etcd endpoint must be refused"
    );
    let redis = cluster_cfg(
        "redis",
        false,
        serde_json::json!({ "url": "  redis://r:6379" }),
    );
    assert!(
        redis.validate_transport_security().is_err(),
        "leading-whitespace plaintext redis url must be refused"
    );
}

#[test]
fn transport_security_accepts_all_https_etcd_endpoints() {
    let cfg = cluster_cfg(
        "etcd",
        false,
        serde_json::json!({ "endpoints": ["https://e1:2379", "https://e2:2379"] }),
    );
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn transport_security_refuses_nats_require_tls_false() {
    let cfg = cluster_cfg(
        "nats",
        false,
        serde_json::json!({ "servers": ["nats://n:4222"], "tls": { "require_tls": false } }),
    );
    let err = cfg
        .validate_transport_security()
        .expect_err("nats require_tls:false must be refused");
    assert!(err.to_string().contains("require_tls"));
}

#[test]
fn transport_security_accepts_nats_default_require_tls() {
    // No `tls` block → the nats plugin requires TLS by default (and a
    // `nats://` URL can still negotiate TLS on the port), so the gateway
    // guard has nothing to refuse. Plaintext nats is an explicit
    // `tls.require_tls: false`, caught by `transport_security_refuses_*`.
    let cfg = cluster_cfg(
        "nats",
        false,
        serde_json::json!({ "servers": ["nats://n:4222"] }),
    );
    assert!(cfg.validate_transport_security().is_ok());
}

#[test]
fn allow_insecure_transport_is_not_forwarded_to_the_plugin_config() {
    // The gateway-only opt-out MUST be consumed as a named field and kept
    // OUT of the flattened `config` map the gateway forwards to the plugin
    // (the plugins enforce `deny_unknown_fields` and would reject it). This
    // pins the serde(flatten) contract the transport guard relies on.
    let yaml = r#"
cluster:
  kind: redis
  allow_insecure_transport: true
  url: rediss://r:6379
  key_prefix: "mcpg:cluster:"
"#;
    let cfg: AppConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.cluster.allow_insecure_transport);
    assert!(
        !cfg.cluster.config.contains_key("allow_insecure_transport"),
        "allow_insecure_transport must not leak into the flattened plugin config map"
    );
    // The kind-specific keys still flow through to the plugin.
    assert_eq!(
        cfg.cluster.config.get("url").and_then(|v| v.as_str()),
        Some("rediss://r:6379")
    );
}

// Operators control sink presence by listing or omitting entries in
// `observability.{logs,traces}.sinks`; omitting the built-in sink kind
// from the list disables it.

#[test]
fn plugin_entry_http_route_config_parses() {
    // Ensure the new `http_route` block deserialises from YAML
    // with every tuning field set. Serde defaults handle the
    // common case (every field absent); this test locks the
    // explicit case so operator-config docs stay authoritative.
    let yaml = r#"
id: dev.mcpg.custom.status
class: http_route
source:
  path: /tmp/nowhere.so
http_route:
  disabled: false
  allow_path_override: true
  max_body_bytes: 65536
  requires_identity: true
"#;
    let entry: PluginEntryConfig = serde_yaml::from_str(yaml).expect("parse entry with http_route");
    let hr = entry.http_route.expect("http_route block parsed");
    assert!(!hr.disabled);
    assert!(hr.allow_path_override);
    assert_eq!(hr.max_body_bytes, Some(65536));
    assert_eq!(hr.requires_identity, Some(true));
}

#[test]
fn plugin_entry_http_route_absent_is_none() {
    // Sanity: an entry without an `http_route:` block
    // deserialises with `http_route = None`, not a
    // default-populated struct. Tests the `skip_serializing_if`
    // hygiene too.
    let yaml = r#"
id: dev.mcpg.custom.gate
class: tool_gate
source:
  path: /tmp/nowhere.so
"#;
    let entry: PluginEntryConfig =
        serde_yaml::from_str(yaml).expect("parse entry without http_route");
    assert!(entry.http_route.is_none());
}

#[test]
fn plugin_entries_reject_invalid_kind() {
    // Validation operates on `Vec<PluginEntryConfig>` directly via
    // `validate_plugins`.
    let entries = vec![PluginEntryConfig {
        id: "com.test.bad".into(),
        r#ref: None,
        kind: "docker".into(),
        class: "tool_gate".into(),
        source: PluginSourceConfig::default(),
        config: serde_json::json!({}),
        signature: None,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }];
    let err = crate::config::plugins::validate_plugins(&entries).unwrap_err();
    assert!(err.to_string().contains("native"), "got: {err}");
}

#[test]
fn plugin_entries_reject_invalid_class() {
    let entries = vec![PluginEntryConfig {
        id: "com.test.bad-class".into(),
        r#ref: None,
        kind: "wasm".into(),
        class: "filter".into(),
        source: PluginSourceConfig::default(),
        config: serde_json::json!({}),
        signature: None,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }];
    let err = crate::config::plugins::validate_plugins(&entries).unwrap_err();
    assert!(
        err.to_string().contains("tool_gate"),
        "expected class validation error, got: {err}"
    );
}

#[test]
fn plugin_entries_accept_valid_entries() {
    let entries = vec![
        PluginEntryConfig {
            id: "dev.mcpg.payment.mpp".into(),
            r#ref: None,
            kind: "native".into(),
            class: "tool_gate".into(),
            source: PluginSourceConfig {
                path: Some("/opt/mcpg/plugins/payment.so".into()),
                oci: None,
            },
            config: serde_json::json!({"method": "tempo"}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        },
        PluginEntryConfig {
            id: "com.acme.transform".into(),
            r#ref: None,
            kind: "wasm".into(),
            class: "transform".into(),
            source: PluginSourceConfig {
                path: Some("/opt/mcpg/plugins/transform.wasm".into()),
                oci: None,
            },
            config: serde_json::json!({}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: Some(PluginResourceLimitsConfig {
                memory_mb: Some(32),
                fuel: Some(5_000_000),
                timeout_ms: Some(100),
            }),
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        },
    ];
    crate::config::plugins::validate_plugins(&entries).unwrap();
}

#[test]
fn plugin_entries_accept_every_canonical_plugin_class() {
    // validate_plugins accepts every snake_case PluginClass variant.
    // Catches the regression where the allowlist falls behind a new
    // variant.
    let canonical_classes = [
        "tool_gate",
        "transform",
        "identity_provider",
        "backend",
        "watch_strategy",
        "http_route",
        "audit_sink",
        "store",
        "cache",
        "telemetry_sink",
        "log_sink",
        "metrics_sink",
        "secret_provider",
        "config_provider",
        "transport",
        "policy_engine",
        "cluster",
        "catalog_provider",
        "credential_issuer",
        "approval_notifier",
        "content_store",
    ];
    for class in canonical_classes {
        let entries = vec![PluginEntryConfig {
            id: format!("dev.test.{class}"),
            r#ref: None,
            kind: "native".into(),
            class: class.into(),
            source: PluginSourceConfig {
                path: Some("/opt/plugin.so".into()),
                oci: None,
            },
            config: serde_json::json!({}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        }];
        crate::config::plugins::validate_plugins(&entries)
            .unwrap_or_else(|e| panic!("expected `class: {class}` to validate, got: {e}"));
    }
}

#[test]
fn plugin_entries_reject_legacy_class_forms() {
    // Legacy hyphen/abbreviated class strings are no longer special-
    // cased; they fall through to the generic unrecognised-class error.
    for legacy in [
        "tool-gate",
        "identity",
        "http-route",
        "binding",
        "cluster_backend",
    ] {
        let entries = vec![PluginEntryConfig {
            id: "dev.test.legacy".into(),
            r#ref: None,
            kind: "native".into(),
            class: legacy.into(),
            source: PluginSourceConfig {
                path: Some("/opt/plugin.so".into()),
                oci: None,
            },
            config: serde_json::json!({}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        }];
        let err = crate::config::plugins::validate_plugins(&entries).unwrap_err();
        assert!(
            err.to_string().contains("not a recognised PluginClass"),
            "expected generic class rejection for '{legacy}', got: {err}"
        );
    }
}

#[test]
fn plugin_entries_accept_explicit_ref() {
    // Multi-instance: alias `cedar.tenant-a` referencing manifest id
    // `dev.mcpg.policy.cedar`. Validator accepts.
    let entries = vec![PluginEntryConfig {
        id: "cedar.tenant-a".into(),
        r#ref: Some("dev.mcpg.policy.cedar".into()),
        kind: "native".into(),
        class: "policy_engine".into(),
        source: PluginSourceConfig {
            path: Some("/opt/cedar.so".into()),
            oci: None,
        },
        config: serde_json::json!({}),
        signature: None,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }];
    crate::config::plugins::validate_plugins(&entries).unwrap();
}

#[test]
fn plugin_entries_reject_non_reverse_dns_ref() {
    // `ref` must be reverse-DNS (at least one dot, lowercase).
    let entries = vec![PluginEntryConfig {
        id: "alias-x".into(),
        r#ref: Some("not_reverse_dns".into()),
        kind: "native".into(),
        class: "policy_engine".into(),
        source: PluginSourceConfig {
            path: Some("/opt/p.so".into()),
            oci: None,
        },
        config: serde_json::json!({}),
        signature: None,
        granted_capabilities: Vec::new(),
        limits: None,
        enforce: true,
        disabled: false,
        inline_dispatch: false,
        http_route: None,
        observability: None,
        ffi_limits: None,
    }];
    let err = crate::config::plugins::validate_plugins(&entries).unwrap_err();
    assert!(
        err.to_string().contains("reverse-DNS"),
        "expected reverse-DNS hint, got: {err}"
    );
}

#[test]
fn plugin_entries_reject_duplicate_alias() {
    // Alias uniqueness — two entries with the same `id` (alias) are
    // refused even when their `ref` differs.
    let entries = vec![
        PluginEntryConfig {
            id: "shared-alias".into(),
            r#ref: Some("dev.mcpg.policy.cedar".into()),
            kind: "native".into(),
            class: "policy_engine".into(),
            source: PluginSourceConfig {
                path: Some("/opt/c.so".into()),
                oci: None,
            },
            config: serde_json::json!({}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        },
        PluginEntryConfig {
            id: "shared-alias".into(),
            r#ref: Some("dev.mcpg.policy.casbin".into()),
            kind: "native".into(),
            class: "policy_engine".into(),
            source: PluginSourceConfig {
                path: Some("/opt/c2.so".into()),
                oci: None,
            },
            config: serde_json::json!({}),
            signature: None,
            granted_capabilities: Vec::new(),
            limits: None,
            enforce: true,
            disabled: false,
            inline_dispatch: false,
            http_route: None,
            observability: None,
            ffi_limits: None,
        },
    ];
    let err = crate::config::plugins::validate_plugins(&entries).unwrap_err();
    assert!(
        err.to_string().contains("alias"),
        "expected alias-duplication hint, got: {err}"
    );
}

// --- Schema registry tests ---

#[test]
fn validate_schema_entry_requires_exactly_one_source() {
    let mut config = AppConfig::default();
    config.schema_registry.insert(
        "empty".to_owned(),
        SchemaEntry {
            inline: None,
            file: None,
            url: None,
        },
    );
    assert!(config.validate().is_err());
}

#[test]
fn validate_schema_entry_rejects_multiple_sources() {
    let mut config = AppConfig::default();
    config.schema_registry.insert(
        "multi".to_owned(),
        SchemaEntry {
            inline: Some(serde_json::json!({"type": "object"})),
            file: Some("schema.json".to_owned()),
            url: None,
        },
    );
    assert!(config.validate().is_err());
}

#[test]
fn validate_schema_entry_accepts_inline() {
    let mut config = AppConfig::default();
    config.schema_registry.insert(
        "ok".to_owned(),
        SchemaEntry {
            inline: Some(serde_json::json!({"type": "object", "properties": {}})),
            file: None,
            url: None,
        },
    );
    config.validate().unwrap();
}

#[test]
fn validate_schema_ref_rejects_unknown_ref() {
    let mut config = AppConfig::default();
    config.mcp.capabilities.tools.push(BackendConfig {
        name: "tool1".to_owned(),
        title: None,
        description: "test".to_owned(),
        input_schema: Some(serde_json::json!({"$schema_ref": "nonexistent"})),
        output_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!("ok"),
                error: false,
                error_message: None,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
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
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    });
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("$ref 'nonexistent' not found"));
}

#[test]
fn validate_schema_ref_accepts_valid_ref() {
    let mut config = AppConfig::default();
    config.schema_registry.insert(
        "my-schema".to_owned(),
        SchemaEntry {
            inline: Some(serde_json::json!({"type": "object"})),
            file: None,
            url: None,
        },
    );
    config.mcp.capabilities.tools.push(BackendConfig {
        name: "tool1".to_owned(),
        title: None,
        description: "test".to_owned(),
        input_schema: Some(serde_json::json!({"$schema_ref": "my-schema"})),
        output_schema: None,
        backend: BackendImpl::from_typed(
            "mock",
            MockBackendConfig {
                response: serde_json::json!("ok"),
                error_message: None,
                error: false,
                delay_ms: 0,
                passthrough: false,
            },
        ),
        governance: BackendGovernanceConfig::default(),
        retry: None,
        content_storage: None,
        cache: None,
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
        resource_size: None,
        resource_annotations: None,
        mcp_app_url: None,
    });
    config.validate().unwrap();
}

/// `validate_bindings` skips every `$schema_ref` form, so the resolution
/// pass is the only thing standing between a registry schema and the
/// compiler. An off-document `$ref` inside a registry entry must be
/// refused there — reaching the compiler would mean an outbound fetch from
/// inside the boot task.
#[tokio::test]
async fn resolve_schema_refs_rejects_an_off_document_ref_in_a_registry_entry() {
    let mut config = AppConfig::default();
    config.schema_registry.insert(
        "poisoned".to_owned(),
        SchemaEntry {
            inline: Some(serde_json::json!({
                "type": "object",
                "properties": { "a": { "$ref": "http://169.254.169.254/latest/meta-data" } }
            })),
            file: None,
            url: None,
        },
    );
    let err = config
        .resolve_schema_refs(None)
        .await
        .expect_err("off-document ref must be refused");
    assert!(err.to_string().contains("off-document"), "got: {}", err);
}

#[test]
fn validate_resource_template_requires_uri_template() {
    let mut config = AppConfig::default();
    config
        .mcp
        .capabilities
        .resource_templates
        .push(BackendConfig {
            name: "weather-city".to_owned(),
            title: None,
            description: "Forecast by city".to_owned(),
            input_schema: None,
            output_schema: None,
            backend: BackendImpl::from_typed(
                "mock",
                MockBackendConfig {
                    error_message: None,
                    response: serde_json::json!("sunny"),
                    error: false,
                    delay_ms: 0,
                    passthrough: false,
                },
            ),
            governance: BackendGovernanceConfig::default(),
            retry: None,
            content_storage: None,
            cache: None,
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
            resource_size: None,
            resource_annotations: None,
            mcp_app_url: None,
        });
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("resource_template bindings require a non-empty uri_template")
    );
}

#[test]
fn validate_resource_template_accepts_valid_config() {
    let mut config = AppConfig::default();
    config
        .mcp
        .capabilities
        .resource_templates
        .push(BackendConfig {
            name: "weather-city".to_owned(),
            title: Some("Weather by city".to_owned()),
            description: "Forecast by city".to_owned(),
            input_schema: None,
            output_schema: None,
            backend: BackendImpl::from_typed(
                "mock",
                MockBackendConfig {
                    response: serde_json::json!("sunny"),
                    error: false,
                    error_message: None,
                    delay_ms: 0,
                    passthrough: false,
                },
            ),
            governance: BackendGovernanceConfig::default(),
            retry: None,
            content_storage: None,
            cache: None,
            quotas: None,
            annotations: None,
            task_support: None,
            prompt_arguments: None,
            uri: None,
            mime_type: Some("application/json".to_owned()),
            uri_template: Some("weather://{city}/forecast".to_owned()),
            variable_completions: None,
            watch: None,
            icons: None,
            descriptor_meta: None,
            resource_size: None,
            resource_annotations: None,
            mcp_app_url: None,
        });
    config.validate().unwrap();
}

// ---- sql_tx config validation ------------------------------

/// JWKS without an audience and without the explicit escape
/// hatch must fail validation.
#[test]
fn jwks_rejects_missing_audience_by_default() {
    let cfg = JwksConfig {
        url: "https://idp.example.com/.well-known/jwks.json".to_owned(),
        keys_json: None,
        issuer: Some("https://idp.example.com".to_owned()),
        audience: None,
        header_name: super::access::default_jwks_header_name(),
        header_prefix: super::access::default_jwks_header_prefix(),
        allow_missing_audience: false,
    };
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("audience is required"), "got: {err}");
}

#[test]
fn jwks_accepts_missing_audience_when_escape_hatch_set() {
    let cfg = JwksConfig {
        url: "https://idp.example.com/.well-known/jwks.json".to_owned(),
        keys_json: None,
        issuer: Some("https://idp.example.com".to_owned()),
        audience: None,
        header_name: super::access::default_jwks_header_name(),
        header_prefix: super::access::default_jwks_header_prefix(),
        allow_missing_audience: true,
    };
    cfg.validate().unwrap();
}

// -- SignalToggle::validate ------------------------------------
// `kind`-aware validation: metrics rejects level outright (metrics-rs
// has no severity); logs / traces accept it. Other rules (sinks×mode
// interplay, hint on enabled+level) still run regardless of kind.

#[test]
fn signal_toggle_metrics_rejects_level() {
    let toggle = SignalToggle {
        enabled: true,
        level: Some("warn".into()),
        mode: SinkMode::Inherit,
        sinks: Vec::new(),
    };
    let err = toggle.validate(SignalKind::Metrics).unwrap_err();
    assert!(
        err.contains("level") && err.contains("metrics"),
        "expected metrics+level rejection, got: {err}"
    );
}

#[test]
fn signal_toggle_logs_accepts_level() {
    let toggle = SignalToggle {
        enabled: true,
        level: Some("debug".into()),
        mode: SinkMode::Inherit,
        sinks: Vec::new(),
    };
    toggle.validate(SignalKind::Logs).unwrap();
}

#[test]
fn signal_toggle_traces_accepts_level() {
    let toggle = SignalToggle {
        enabled: true,
        level: Some("error".into()),
        mode: SinkMode::Inherit,
        sinks: Vec::new(),
    };
    toggle.validate(SignalKind::Traces).unwrap();
}

#[test]
fn signal_toggle_metrics_without_level_accepted() {
    let toggle = SignalToggle {
        enabled: true,
        level: None,
        mode: SinkMode::Replace,
        sinks: vec!["sink.x".into()],
    };
    toggle.validate(SignalKind::Metrics).unwrap();
}

#[test]
fn signal_toggle_replace_with_empty_sinks_rejected_for_all_kinds() {
    let toggle = SignalToggle {
        enabled: true,
        level: None,
        mode: SinkMode::Replace,
        sinks: Vec::new(),
    };
    for k in [SignalKind::Logs, SignalKind::Metrics, SignalKind::Traces] {
        let err = toggle.validate(k).unwrap_err();
        assert!(err.contains("Replace"), "kind={k:?} got: {err}");
    }
}

#[test]
fn openapi_binding_parses_validates_and_routes() {
    use super::backend::BackendConfig;

    // Operator-facing Tier-1 shape: a tool binding referencing a source +
    // operation registered in the openapi plugin's own config.
    let yaml = r#"
name: petstore.getPetById
description: Get a pet by id
backend:
  kind: openapi
  source: petstore
  operation: getPetById
"#;
    let binding: BackendConfig = serde_yaml::from_str(yaml).expect("parse openapi binding");
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

    // Route construction maps the binding to OpenapiCall under its name.
    let registry = super::super::backends::CapabilityRegistry::new(
        false,
        Default::default(),
        Default::default(),
        std::slice::from_ref(&binding),
        &[],
        &[],
        &[],
        None,
    );
    assert!(matches!(
        registry.tool_route("petstore.getPetById"),
        Some(super::super::backends::BackendInvocationRoute::OpenapiCall { .. })
    ));
}

#[test]
fn pipeline_plugin_transform_step_parses() {
    use super::backend::{BackendConfig, PipelineStepConfig};
    let yaml = r#"
name: order.flow
description: pipeline with a jsonata reshape step
backend:
  kind: pipeline
  steps:
    - kind: plugin_transform
      id: reshape
      plugin: dev.mcpg.transform.jsonata
      config: { expression: "{ \"ids\": steps.fetch.output.orders.id }" }
"#;
    let binding: BackendConfig = serde_yaml::from_str(yaml).expect("parse pipeline binding");
    let p = serde_json::from_value::<PipelineBackendConfig>(serde_json::Value::Object(
        binding.backend.spec.clone(),
    ))
    .expect("pipeline backend");
    let step = p
        .steps
        .iter()
        .find(|s| s.id() == "reshape")
        .expect("reshape step");
    assert_eq!(step.type_label(), "plugin_transform");
    match step {
        PipelineStepConfig::PluginTransform(s) => {
            assert_eq!(s.plugin, "dev.mcpg.transform.jsonata");
            assert!(s.config.get("expression").is_some());
        }
        _ => panic!("expected PluginTransform step"),
    }
}

// ---- cloud: block (mcpg.cloud managed-fleet identity) ----

#[test]
fn cloud_block_absent_is_default_and_validates() {
    let cfg = AppConfig::load_from_yaml_str("mcp: {}\n").expect("parse");
    assert_eq!(cfg.cloud, CloudConfig::default());
    assert!(AppConfig::default().validate().is_ok());
}

#[test]
fn bare_cloud_key_does_not_panic() {
    let cfg = AppConfig::load_from_yaml_str("cloud: {}\n").expect("bare cloud parses");
    assert_eq!(cfg.cloud, CloudConfig::default());
}

#[test]
fn full_cloud_block_round_trips() {
    let yaml = r#"
cloud:
  instance_id: "inst-0190abcd"
  name: "Acme prod"
  subdomain: "inst-0190abcd"
  custom_domains:
    - "mcp.acme.com"
  tenant: "acme"
  workspace: "payments"
  environment: "prod"
  region: "us-east-1"
  tier: "pro"
  isolation: "dedicated"
  provenance:
    cluster_id: "cell-use1-a"
    namespace: "tenant-acme"
    external_url: "https://inst-0190abcd.mcpg.cloud/mcp"
    provisioned_at: "2026-06-08T00:00:00Z"
    managed_by: "mcpg-provisioner"
"#;
    let cfg = AppConfig::load_from_yaml_str(yaml).expect("parse full cloud");
    assert_eq!(
        cfg.cloud.instance_id,
        Some(InstanceId("inst-0190abcd".into()))
    );
    assert_eq!(cfg.cloud.subdomain.as_deref(), Some("inst-0190abcd"));
    assert_eq!(cfg.cloud.custom_domains, vec!["mcp.acme.com".to_string()]);
    assert_eq!(cfg.cloud.tier, CloudTier::Pro);
    assert_eq!(cfg.cloud.isolation, CloudIsolation::Dedicated);
    assert_eq!(
        cfg.cloud.provenance.external_url.as_deref(),
        Some("https://inst-0190abcd.mcpg.cloud/mcp")
    );
    // round-trip via serde_json
    let v = serde_json::to_value(&cfg.cloud).expect("serialize");
    let reparsed: CloudConfig = serde_json::from_value(v).expect("reparse");
    assert_eq!(cfg.cloud, reparsed);
    cfg.cloud.validate().expect("valid");
}

#[test]
fn unknown_field_under_cloud_rejected() {
    assert!(
        AppConfig::load_from_yaml_str("cloud:\n  bogus: 1\n").is_err(),
        "unknown field under cloud must be rejected"
    );
}

#[test]
fn cloud_inert_when_absent() {
    let without = AppConfig::load_from_yaml_str("mcp: {}\n").expect("parse");
    let with_empty = AppConfig::load_from_yaml_str("mcp: {}\ncloud: {}\n").expect("parse");
    assert_eq!(without.canonical_sha256(), with_empty.canonical_sha256());
}

#[test]
fn cloud_instance_id_and_slugs_must_be_dns_labels() {
    let bad_id = AppConfig {
        cloud: CloudConfig {
            instance_id: Some(InstanceId("Bad_Id!".into())),
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(bad_id.validate().is_err());

    let bad_tenant = AppConfig {
        cloud: CloudConfig {
            tenant: Some("Bad Tenant".into()),
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(bad_tenant.validate().is_err());

    let good = AppConfig {
        cloud: CloudConfig {
            instance_id: Some(InstanceId("prod-1-abc123".into())),
            subdomain: Some("prod-1-abc123".into()),
            tenant: Some("acme".into()),
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(good.validate().is_ok());
}

#[test]
fn cloud_custom_domain_validated() {
    let bad = AppConfig {
        cloud: CloudConfig {
            custom_domains: vec!["bad_domain.com".into()],
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(bad.validate().is_err());

    let good = AppConfig {
        cloud: CloudConfig {
            custom_domains: vec!["mcp.acme.com".into(), "api.acme.example.co".into()],
            ..Default::default()
        },
        ..AppConfig::default()
    };
    assert!(good.validate().is_ok());
}

#[test]
fn cloud_provenance_field_parses() {
    let cfg = AppConfig::load_from_yaml_str(
        "cloud:\n  provenance:\n    external_url: \"https://x.mcpg.cloud/mcp\"\n",
    )
    .expect("parse");
    assert_eq!(
        cfg.cloud.provenance.external_url.as_deref(),
        Some("https://x.mcpg.cloud/mcp")
    );
}

// ── Tool-schema hardening ─────────────────────────────────────────

/// Build a single-tool config whose tool descriptor is customizable
/// via the closure, so schema-hardening tests stay concise.
fn config_with_tool(customize: impl FnOnce(&mut BackendConfig)) -> AppConfig {
    let mut binding = BackendConfig {
        name: "test.tool".to_owned(),
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
        governance: BackendGovernanceConfig::default(),
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
    };
    customize(&mut binding);
    AppConfig {
        mcp: crate::config::McpConfig {
            capabilities: McpCapabilitiesConfig {
                tools: vec![binding],
                ..McpCapabilitiesConfig::default()
            },
            ..crate::config::McpConfig::default()
        },
        ..AppConfig::default()
    }
}

#[test]
fn validate_rejects_uncompilable_output_schema_fail_closed() {
    let cfg = config_with_tool(|b| {
        b.output_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "x": { "type": "not_a_valid_type" } }
        }));
    });
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("output_schema"), "{err}");
}

#[test]
fn validate_rejects_network_ref_in_input_schema() {
    let cfg = config_with_tool(|b| {
        b.input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "x": { "$ref": "https://evil.example/s.json" } }
        }));
    });
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("off-document"), "{err}");
}

#[test]
fn validate_rejects_overly_wide_composition() {
    let branches: Vec<serde_json::Value> = (0
        ..(crate::config::schema_safety::MAX_COMPOSITION_BREADTH + 1))
        .map(|_| serde_json::json!({ "type": "object" }))
        .collect();
    let cfg = config_with_tool(|b| {
        b.input_schema = Some(serde_json::json!({ "allOf": branches }));
    });
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("breadth bound"), "{err}");
}

#[test]
fn validate_rejects_http_icon_src() {
    let cfg = config_with_tool(|b| {
        b.icons = Some(vec![BackendIconConfig {
            src: "http://insecure.example/icon.png".to_owned(),
            mime_type: None,
            sizes: None,
            theme: None,
        }]);
    });
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("icons"), "{err}");
}

#[test]
fn validate_accepts_https_and_data_icon_src() {
    let cfg = config_with_tool(|b| {
        b.icons = Some(vec![
            BackendIconConfig {
                src: "https://cdn.example/icon.png".to_owned(),
                mime_type: None,
                sizes: None,
                theme: None,
            },
            BackendIconConfig {
                src: "data:image/png;base64,AAAA".to_owned(),
                mime_type: None,
                sizes: None,
                theme: None,
            },
        ]);
    });
    assert!(cfg.validate().is_ok());
}

#[test]
fn validate_accepts_in_document_ref() {
    let cfg = config_with_tool(|b| {
        b.input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "x": { "$ref": "#/$defs/Foo" } },
            "$defs": { "Foo": { "type": "string" } }
        }));
    });
    assert!(cfg.validate().is_ok());
}

// -- MCPG_ environment overlay scoping ------------------------------

#[test]
fn env_key_root_takes_the_first_path_segment() {
    assert_eq!(
        super::env_key_root("GOVERNANCE__ACCESS__JWKS__URL"),
        "governance"
    );
    assert_eq!(super::env_key_root("MCP"), "mcp");
    assert_eq!(super::env_key_root("PORT"), "port");
    // `_` is not the separator, so a tool-family name stays one segment
    // and cannot be mistaken for the `cloud` config root.
    assert_eq!(super::env_key_root("CLOUD_TOKEN"), "cloud_token");
}

#[test]
fn known_config_roots_match_the_struct() {
    let roots = AppConfig::known_config_roots();
    for expected in [
        "mcp",
        "governance",
        "gateway",
        "observability",
        "feature_flags",
        "debug",
        "schema_registry",
        "storage",
        "cluster",
        "credentials",
        "license",
        "plugins",
        "cloud",
        "usage_reporting",
    ] {
        assert!(roots.contains(expected), "missing config root: {expected}");
    }
    assert_eq!(
        roots.len(),
        14,
        "AppConfig gained or lost a top-level field: {roots:?}"
    );
}

/// A stray `MCPG_`-prefixed variable — from a PaaS, another tool, or an
/// operator's naming instinct — must not abort boot. Only variables naming a
/// real config root take part in the overlay.
#[test]
fn unknown_mcpg_env_var_does_not_abort_load() {
    let _env = env_guard();
    // SAFETY: nextest runs each test in its own process, and the variable is
    // removed before returning.
    unsafe { std::env::set_var("MCPG_PORT", "9999") };
    let loaded = AppConfig::load_sources(&[]);
    unsafe { std::env::remove_var("MCPG_PORT") };
    assert!(
        loaded.is_ok(),
        "an unrecognised MCPG_ variable must be ignored, not fatal: {:?}",
        loaded.err()
    );
}

/// The strictness that matters is kept: a typo *inside* a recognised subtree
/// still fails, because that variable really was aimed at the config.
#[test]
fn typo_inside_a_known_root_still_fails_load() {
    let _env = env_guard();
    unsafe { std::env::set_var("MCPG_GATEWAY__SERVER__NOT_A_FIELD", "1") };
    let loaded = AppConfig::load_sources(&[]);
    unsafe { std::env::remove_var("MCPG_GATEWAY__SERVER__NOT_A_FIELD") };
    let err = loaded.expect_err("a typo under gateway.server must fail closed");
    let msg = format!("{err:#}");
    assert!(msg.contains("not_a_field"), "got: {msg}");
}

#[test]
fn ignored_env_overrides_reports_strays_but_not_tool_family_vars() {
    let _env = env_guard();
    unsafe {
        std::env::set_var("MCPG_PORT", "9999");
        std::env::set_var("MCPG_STATE_DIR", "/tmp/state");
        std::env::set_var("MCPG_GATEWAY__SERVER__BIND_ADDRESS", "127.0.0.1:1");
        std::env::set_var(
            "MCPG_DEFAULT_PLUGIN_REGISTRY",
            "registry.example.com/plugins",
        );
    }
    let ignored = AppConfig::ignored_env_overrides();
    unsafe {
        std::env::remove_var("MCPG_PORT");
        std::env::remove_var("MCPG_STATE_DIR");
        std::env::remove_var("MCPG_GATEWAY__SERVER__BIND_ADDRESS");
        std::env::remove_var("MCPG_DEFAULT_PLUGIN_REGISTRY");
    }
    assert!(ignored.contains(&"MCPG_PORT".to_owned()), "{ignored:?}");
    assert!(
        !ignored.contains(&"MCPG_STATE_DIR".to_owned()),
        "tool-family vars are not strays: {ignored:?}"
    );
    assert!(
        !ignored.contains(&"MCPG_GATEWAY__SERVER__BIND_ADDRESS".to_owned()),
        "a real override is not a stray: {ignored:?}"
    );
    // It addresses no config root, but it does take effect via the
    // `plugin_registry.default_registry` serde default.
    assert!(
        !ignored.contains(&"MCPG_DEFAULT_PLUGIN_REGISTRY".to_owned()),
        "a variable that does take effect is not a stray: {ignored:?}"
    );
}

/// The overlay must still *work*: scoping it to known roots is only correct
/// if a variable naming a real root still reaches the config.
#[test]
fn env_override_under_a_known_root_still_applies() {
    let _env = env_guard();
    unsafe { std::env::set_var("MCPG_GATEWAY__SERVER__BIND_ADDRESS", "127.0.0.1:9911") };
    let loaded = AppConfig::load_sources(&[]);
    unsafe { std::env::remove_var("MCPG_GATEWAY__SERVER__BIND_ADDRESS") };
    assert_eq!(
        loaded.expect("config loads").gateway.server.bind_address,
        "127.0.0.1:9911"
    );
}

/// `cloud.tier` mirrors the licensing vocabulary, which has no `free` — that
/// name was a fifth plan taxonomy living only in this enum. It still parses,
/// because a config written before the rename must not fail to load.
#[test]
fn cloud_tier_speaks_the_licensing_vocabulary_and_still_accepts_free() {
    let load = |tier: &str| {
        AppConfig::load_from_yaml_str(&format!("cloud:\n  tier: {tier}\n"))
            .expect("parse cloud tier")
            .cloud
            .tier
    };
    assert_eq!(load("community"), CloudTier::Community);
    assert_eq!(
        load("free"),
        CloudTier::Community,
        "an existing config saying `free` keeps loading"
    );
    for (name, want) in [
        ("pro", CloudTier::Pro),
        ("team", CloudTier::Team),
        ("enterprise", CloudTier::Enterprise),
    ] {
        assert_eq!(load(name), want, "{name}");
    }
    // The vocabulary is closed: a plan name that does not exist is refused
    // rather than silently defaulting to unspecified.
    assert!(AppConfig::load_from_yaml_str("cloud:\n  tier: plus\n").is_err());
}
