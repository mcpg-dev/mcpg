use super::*;
use crate::config::{InteractiveLoginConfig, InteractiveStoreConfig, InteractiveStoreKind};
use crate::runtime::authorization_server::state::{
    GrantId, KeyringSource, PrincipalGrantRecord, RevocationReason, RevokedId, StateBackend, keys,
};
use crate::runtime::authorization_server::{AuthorizationServer, InteractiveState};
use std::time::Duration;

const STATE_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const TTL: Duration = Duration::from_secs(600);

/// An authorization server with interactive sign-in through one IdP, on
/// `cluster_kind`.
fn login_config(cluster_kind: &str) -> AppConfig {
    let mut config: AppConfig = serde_yaml::from_str(
        r#"
governance:
  access:
    resource_metadata:
      resource: https://mcp.example.com/mcp
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: ema-signing-secret-0123456789abcdef
      trusted_idps:
        - issuer: https://acme.okta.com
          allowed_hosts: [acme.okta.com]
          login:
            client_id: 0oa1agent
            client_secret: login-client-secret-0123
      clients:
        - client_id: mcp-client
"#,
    )
    .expect("config parses");
    config.cluster.kind = cluster_kind.to_owned();
    config
}

fn interactive(config: &mut AppConfig) -> &mut InteractiveLoginConfig {
    config
        .governance
        .access
        .authorization_server
        .as_mut()
        .expect("authorization_server")
        .interactive
        .get_or_insert_with(InteractiveLoginConfig::default)
}

fn with_store(mut config: AppConfig, kind: InteractiveStoreKind, dir: Option<&Path>) -> AppConfig {
    interactive(&mut config).store = Some(InteractiveStoreConfig {
        kind,
        dir: dir.map(|dir| dir.display().to_string()),
    });
    config
}

fn with_state_key(mut config: AppConfig) -> AppConfig {
    interactive(&mut config).state_keys =
        serde_yaml::from_str(&format!("- kid: k1\n  secret: {STATE_KEY}\n"))
            .expect("state key parses");
    config
}

fn plaintext() -> StateEncryption {
    StateEncryption {
        cipher: None,
        allow_plaintext_reads: false,
    }
}

fn single_node() -> Arc<dyn mcpg_cluster_api::ClusterBackend> {
    crate::builtins::cluster_single_node::SingleNodeClusterBackend::new()
}

fn wire(
    config: &AppConfig,
    coordinator: Option<&Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    previous: Option<&AuthorizationServer>,
) -> Result<Arc<AuthorizationServer>> {
    wire_ema_authorization_server(config, coordinator, &plaintext(), &None, previous)
        .map(|server| server.expect("configured"))
}

/// Wire `config` as a fresh process would, once the tasks of the state
/// that last held its file store have let the store go.
async fn wire_after_restart(config: &AppConfig) -> Arc<AuthorizationServer> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match wire(config, Some(&single_node()), None) {
            Ok(server) => return server,
            Err(error)
                if std::time::Instant::now() < deadline
                    && format!("{error:#}").contains("another gateway process") =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => panic!("wiring after a restart failed: {error:#}"),
        }
    }
}

fn state(server: &AuthorizationServer) -> &InteractiveState {
    server
        .interactive_state()
        .expect("interactive sign-in has state")
}

fn record() -> PrincipalGrantRecord {
    PrincipalGrantRecord { created: 42 }
}

#[tokio::test]
async fn a_server_without_a_login_idp_has_no_sign_in_state() {
    let mut config = login_config("single_node");
    config
        .governance
        .access
        .authorization_server
        .as_mut()
        .expect("authorization_server")
        .trusted_idps[0]
        .login = None;
    let server = wire(&config, Some(&single_node()), None).expect("wires");
    assert!(server.interactive_state().is_none());
}

#[tokio::test]
async fn the_server_knows_whether_a_federation_keeps_the_idp_sign_in() {
    let mut config = with_store(
        login_config("single_node"),
        InteractiveStoreKind::Memory,
        None,
    );
    interactive(&mut config).refresh_tokens.revalidate_with_idp = false;
    let server = wire(&config, Some(&single_node()), None).expect("wires");
    assert!(
        !server.keeps_idp_sign_in(),
        "no revalidation and no federation"
    );

    let federation: AppConfig = serde_yaml::from_str(
        r#"
mcp:
  federations:
    - name: vendor
      upstream:
        url: https://mcp.vendor.example/mcp
        auth:
          mode: oauth_impersonation
          credential: cred://dev.mcpg.credential.oauth-id-jag/vendor
          subject_token: idp_refresh_token
"#,
    )
    .expect("federation parses");
    config.mcp.federations = federation.mcp.federations;
    let server = wire(&config, Some(&single_node()), None).expect("wires");
    assert!(
        server.keeps_idp_sign_in(),
        "an idp_refresh_token federation"
    );
}

#[tokio::test]
async fn the_harness_builder_keeps_sign_in_state_in_process_memory() {
    let ledger = crate::runtime::authorization_server::ReplayLedger::in_process;
    let server = build_ema_authorization_server(&login_config("single_node"), ledger())
        .expect("builds")
        .expect("configured");
    assert_eq!(*state(&server).backend(), StateBackend::InProcess);

    let mut without = login_config("single_node");
    without
        .governance
        .access
        .authorization_server
        .as_mut()
        .expect("authorization_server")
        .trusted_idps[0]
        .login = None;
    let server = build_ema_authorization_server(&without, ledger())
        .expect("builds")
        .expect("configured");
    assert!(server.interactive_state().is_none());
}

#[tokio::test]
async fn a_memory_store_passes_to_the_server_a_reload_builds() {
    let config = with_store(
        login_config("single_node"),
        InteractiveStoreKind::Memory,
        None,
    );
    let at_boot = wire(&config, Some(&single_node()), None).expect("wires");
    let before = state(&at_boot);
    assert_eq!(*before.backend(), StateBackend::InProcess);
    assert_eq!(*before.keyring().source(), KeyringSource::Process);
    let key = keys::principal_grant("alice", &GrantId::generate().expect("gid"));
    before.put(&key, &record(), TTL).await.expect("put");
    let revoked = RevokedId::Grant(GrantId::generate().expect("gid"));
    before
        .record_revocation(&revoked, RevocationReason::Client, 4_102_444_800)
        .await
        .expect("revoke");

    let reloaded = wire(&config, Some(&single_node()), Some(&at_boot)).expect("wires");
    let after = state(&reloaded);
    assert!(after.shares_store_with(before));
    assert!(after.keyring().same_keys(before.keyring()));
    assert!(Arc::ptr_eq(after.revoked(), before.revoked()));
    assert_eq!(after.get(&key).await.expect("get"), Some(record()));
    assert!(after.is_revoked(&revoked));
}

#[tokio::test]
async fn the_single_node_coordinator_store_is_process_memory() {
    let config = with_store(
        login_config("single_node"),
        InteractiveStoreKind::Cluster,
        None,
    );
    let at_boot = wire(&config, Some(&single_node()), None).expect("wires");
    assert_eq!(*state(&at_boot).backend(), StateBackend::InProcess);
    let reloaded = wire(&config, Some(&single_node()), Some(&at_boot)).expect("wires");
    assert!(
        state(&reloaded).shares_store_with(state(&at_boot)),
        "the coordinator a reload rebuilds starts empty, so the store is handed over"
    );
}

#[tokio::test]
async fn a_file_store_keeps_its_generated_key_across_reloads_and_restarts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store_dir = dir.path().join("oauth");
    let config = with_store(
        login_config("single_node"),
        InteractiveStoreKind::File,
        Some(&store_dir),
    );
    let key = keys::principal_grant("alice", &GrantId::generate().expect("gid"));
    {
        let at_boot = wire(&config, Some(&single_node()), None).expect("wires");
        let resolved = std::fs::canonicalize(&store_dir).expect("created");
        assert_eq!(
            *state(&at_boot).backend(),
            StateBackend::File {
                dir: resolved.clone()
            }
        );
        let key_file = resolved.join("state.key");
        assert_eq!(
            *state(&at_boot).keyring().source(),
            KeyringSource::File(key_file.clone())
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&key_file)
                .expect("the key file exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        state(&at_boot)
            .put(&key, &record(), TTL)
            .await
            .expect("put");

        let reloaded = wire(&config, Some(&single_node()), Some(&at_boot))
            .expect("a reload reuses the open store rather than lock it again");
        assert!(state(&reloaded).shares_store_with(state(&at_boot)));
        assert!(
            state(&reloaded)
                .keyring()
                .same_keys(state(&at_boot).keyring())
        );
    }

    let restarted = wire_after_restart(&config).await;
    assert_eq!(
        state(&restarted).get(&key).await.expect("get"),
        Some(record()),
        "the key is read back from state.key, so the records open"
    );
}

/// With no `interactive.store`, a single node keeps sign-in state in a
/// sealed file store in the default directory, under a key generated there.
#[tokio::test]
async fn a_single_node_without_a_store_opens_the_default_file_store() {
    let data = tempfile::tempdir().expect("tempdir");
    let default_dir = data.path().join("oauth");
    let config = login_config("single_node");
    assert!(
        config
            .governance
            .access
            .authorization_server
            .as_ref()
            .expect("authorization_server")
            .interactive
            .is_none()
    );
    let state = interactive_state_under(
        &config,
        Some(&single_node()),
        &plaintext(),
        &None,
        None,
        || default_dir.clone(),
    )
    .expect("wires")
    .expect("sign-in has state");
    let opened = std::fs::canonicalize(&default_dir).expect("the store directory exists");
    assert_eq!(
        *state.backend(),
        StateBackend::File {
            dir: opened.clone()
        }
    );
    assert_eq!(
        *state.keyring().source(),
        KeyringSource::File(opened.join("state.key"))
    );
    assert!(opened.join("state.key").is_file());
}

/// A default file store that does not open refuses the start, and the
/// error names what moves it and what replaces it.
#[tokio::test]
async fn a_default_file_store_that_does_not_open_names_the_settings_that_move_it() {
    let data = tempfile::tempdir().expect("tempdir");
    let in_the_way = data.path().join("read-only-root");
    std::fs::write(&in_the_way, b"").expect("a file where the directory would go");
    let refused = interactive_state_under(
        &login_config("single_node"),
        Some(&single_node()),
        &plaintext(),
        &None,
        None,
        || in_the_way.join("oauth"),
    )
    .expect_err("the default directory cannot be created");
    let message = format!("{refused:#}");
    for needle in [
        "interactive.store.dir",
        "MCPG_STATE_DIR",
        "interactive.store.kind: memory",
        "persistent volume",
    ] {
        assert!(message.contains(needle), "{needle}: {message}");
    }
}

#[tokio::test]
async fn a_file_store_with_configured_keys_generates_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = with_state_key(with_store(
        login_config("single_node"),
        InteractiveStoreKind::File,
        Some(dir.path()),
    ));
    let server = wire(&config, Some(&single_node()), None).expect("wires");
    assert_eq!(
        *state(&server).keyring().source(),
        KeyringSource::Configured
    );
    assert_eq!(state(&server).keyring().sealing_kid(), "k1");
    assert!(!dir.path().join("state.key").exists());
}

#[tokio::test]
async fn a_second_process_on_one_file_store_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = with_store(
        login_config("single_node"),
        InteractiveStoreKind::File,
        Some(dir.path()),
    );
    let _running = wire(&config, Some(&single_node()), None).expect("wires");
    let refused = wire(&config, Some(&single_node()), None).expect_err("the store is taken");
    assert!(
        format!("{refused:#}").contains("open in another gateway process"),
        "{refused:#}"
    );
}

#[tokio::test]
async fn a_clustered_state_lives_in_the_coordinators_store() {
    let coordinator = single_node();
    let config = with_state_key(login_config("redis"));
    let server = wire(&config, Some(&coordinator), None).expect("wires");
    let clustered = state(&server);
    assert_eq!(*clustered.backend(), StateBackend::Cluster);
    let coordinator_kv = coordinator.key_value_store().expect("a KV");
    assert!(Arc::ptr_eq(clustered.store(), &coordinator_kv));

    let key = keys::principal_grant("alice", &GrantId::generate().expect("gid"));
    clustered.put(&key, &record(), TTL).await.expect("put");
    assert!(
        coordinator_kv
            .get(key.as_str())
            .await
            .expect("get")
            .is_some()
    );

    let mut tenant = config.clone();
    tenant.cluster.tenant_segment = Some("t1".to_owned());
    let fenced = wire_ema_authorization_server(
        &tenant,
        Some(&coordinator),
        &plaintext(),
        &tenant.cluster.tenant_segment,
        None,
    )
    .expect("wires")
    .expect("configured");
    let other = keys::principal_grant("bob", &GrantId::generate().expect("gid"));
    state(&fenced)
        .put(&other, &record(), TTL)
        .await
        .expect("put");
    assert!(
        coordinator_kv
            .get(other.as_str())
            .await
            .expect("get")
            .is_none()
    );
    assert!(
        coordinator_kv
            .get(&format!("t.t1/{}", other.as_str()))
            .await
            .expect("get")
            .is_some(),
        "the tenant prefix applies"
    );
}

#[tokio::test]
async fn a_clustered_coordinator_without_a_store_refuses_sign_in() {
    let config = with_state_key(login_config("redis"));
    let refused = wire(&config, None, None).expect_err("single use would hold per replica");
    assert!(
        format!("{refused:#}").contains("exposes none"),
        "{refused:#}"
    );

    let mut degraded = config;
    degraded.cluster.allow_degraded_boot = true;
    let server = wire(&degraded, None, None).expect("boots degraded");
    let unavailable = state(&server);
    assert_eq!(*unavailable.backend(), StateBackend::Unavailable);
    assert!(!unavailable.is_available());
    assert!(
        unavailable
            .claim_once(&keys::transaction_used("s"), TTL)
            .await
            .is_err(),
        "sign-in answers 503 rather than claim per replica"
    );
}

#[tokio::test]
async fn a_clustered_store_without_a_state_key_is_refused() {
    let refused = wire(&login_config("redis"), Some(&single_node()), None)
        .expect_err("stored IdP tokens are never kept unsealed");
    assert!(
        format!("{refused:#}").contains("state_encryption_key_env"),
        "{refused:#}"
    );
    let mut plaintext_allowed = login_config("redis");
    plaintext_allowed.cluster.allow_plaintext_state = true;
    wire(&plaintext_allowed, Some(&single_node()), None)
        .expect_err("allow_plaintext_state does not waive the key");
}

#[tokio::test]
async fn a_reload_that_moves_the_store_keeps_the_revocations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let memory = with_store(
        login_config("single_node"),
        InteractiveStoreKind::Memory,
        None,
    );
    let at_boot = wire(&memory, Some(&single_node()), None).expect("wires");
    let revoked = RevokedId::access_token("jti-1");
    state(&at_boot)
        .record_revocation(&revoked, RevocationReason::Client, 4_102_444_800)
        .await
        .expect("revoke");

    let file = with_store(
        login_config("single_node"),
        InteractiveStoreKind::File,
        Some(dir.path()),
    );
    let moved = wire(&file, Some(&single_node()), Some(&at_boot)).expect("wires");
    assert!(!state(&moved).shares_store_with(state(&at_boot)));
    assert!(matches!(state(&moved).backend(), StateBackend::File { .. }));
    assert!(state(&moved).is_revoked(&revoked));
}
