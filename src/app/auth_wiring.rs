use super::*;

pub(crate) fn map_trust_level(value: TrustLevelConfig) -> RequestTrustLevel {
    match value {
        TrustLevelConfig::Unauthenticated => RequestTrustLevel::Unauthenticated,
        TrustLevelConfig::HeaderAsserted => RequestTrustLevel::HeaderAsserted,
        TrustLevelConfig::Verified => RequestTrustLevel::Verified,
    }
}

pub(crate) async fn build_jwt_verifier(
    config: &AppConfig,
) -> Result<Option<crate::runtime::identity::JwtVerifier>> {
    let jwks_config = match &config.governance.access.jwks {
        Some(jwks) => jwks,
        None => return Ok(None),
    };

    let jwks_json = if let Some(ref keys_json) = jwks_config.keys_json {
        keys_json.clone()
    } else if !jwks_config.url.trim().is_empty() {
        info!(url = %jwks_config.url, "fetching JWKS from URL");
        let response = reqwest::Client::new()
            .get(&jwks_config.url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to fetch JWKS from {}: {}", jwks_config.url, e))?;
        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "JWKS fetch from {} returned status {}",
                jwks_config.url,
                response.status()
            ));
        }
        response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("failed to read JWKS response body: {}", e))?
    } else {
        return Err(anyhow::anyhow!(
            "auth.jwks must have either a 'url' or 'keys_json' field"
        ));
    };

    let source = if jwks_config.keys_json.is_some() {
        "inline"
    } else {
        "url"
    };
    let verifier = crate::runtime::identity::JwtVerifier::from_jwks_json(&jwks_json, jwks_config)?;
    info!(
        key_count = ?verifier,
        source = source,
        "JWT verifier initialized from {} JWKS", source
    );
    Ok(Some(verifier))
}

/// Build the embedded EMA authorization server when
/// `governance.access.authorization_server` is configured. The resource
/// identifiers it mints for come from the PRM (`resource` and
/// `additional_resources`) so minted-token audiences line up with what
/// the gateway publishes. Redeemed ID-JAGs are recorded in `replay`;
/// boot and reload pick it with `ema_replay_ledger`. With a
/// `trusted_idps[].login` block, the state of interactive sign-in lives
/// in process memory. Public so the integration-test harness can wire the
/// same server its hand-built runtime would otherwise lack.
pub fn build_ema_authorization_server(
    config: &AppConfig,
    replay: crate::runtime::authorization_server::ReplayLedger,
) -> Result<Option<std::sync::Arc<crate::runtime::authorization_server::AuthorizationServer>>> {
    let Some(server) = ema_authorization_server(config, replay)? else {
        return Ok(None);
    };
    let state = match server.login_idp() {
        Some(_) => Some(
            crate::runtime::authorization_server::InteractiveState::in_memory(server.issuer())?,
        ),
        None => None,
    };
    Ok(Some(std::sync::Arc::new(
        server.with_interactive_state(state),
    )))
}

/// [`build_ema_authorization_server`] whose interactive sign-in keeps its
/// state in `state`: servers over one state's store and keys stand for the
/// replicas of one cluster. Public for the integration-test harness.
pub fn build_ema_authorization_server_with_state(
    config: &AppConfig,
    replay: crate::runtime::authorization_server::ReplayLedger,
    state: crate::runtime::authorization_server::InteractiveState,
) -> Result<Option<std::sync::Arc<crate::runtime::authorization_server::AuthorizationServer>>> {
    Ok(ema_authorization_server(config, replay)?
        .map(|server| std::sync::Arc::new(server.with_interactive_state(Some(state)))))
}

fn ema_authorization_server(
    config: &AppConfig,
    replay: crate::runtime::authorization_server::ReplayLedger,
) -> Result<Option<crate::runtime::authorization_server::AuthorizationServer>> {
    let Some(ref authz_config) = config.governance.access.authorization_server else {
        return Ok(None);
    };
    let server = crate::runtime::authorization_server::AuthorizationServer::from_config(
        authz_config,
        config.governance.access.resource_metadata.as_ref(),
        replay,
    )?
    .with_federated_idp_sessions(
        !crate::config::interactive_login::idp_subject_token_users(config).is_empty(),
    )
    .with_request_timeout(std::time::Duration::from_millis(
        config.gateway.server.request_timeout_ms,
    ));
    info!(server = ?server, "EMA authorization server initialized");
    Ok(Some(server))
}

/// `config` carrying `resolved`, the `governance.access.authorization_server`
/// block with its placeholders resolved, for [`wire_ema_authorization_server`]
/// alone: the copy ends with the wiring, so resolved keys and secrets never
/// reach the config the runtime keeps.
pub(crate) fn with_resolved_authorization_server(
    config: &AppConfig,
    resolved: Option<crate::config::AuthorizationServerConfig>,
) -> std::borrow::Cow<'_, AppConfig> {
    match resolved {
        Some(server) => {
            let mut config = config.clone();
            config.governance.access.authorization_server = Some(server);
            std::borrow::Cow::Owned(config)
        }
        None => std::borrow::Cow::Borrowed(config),
    }
}

/// Boot and reload: [`build_ema_authorization_server`] over the ledger
/// [`ema_replay_ledger`] picks, with the state of interactive sign-in
/// [`interactive_state`] resolves. `previous` is the server a reload
/// replaces.
pub(crate) fn wire_ema_authorization_server(
    config: &AppConfig,
    coordinator: Option<&Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    state_cipher: &StateEncryption,
    tenant_seg: &Option<String>,
    previous: Option<&crate::runtime::authorization_server::AuthorizationServer>,
) -> Result<Option<std::sync::Arc<crate::runtime::authorization_server::AuthorizationServer>>> {
    if config.governance.access.authorization_server.is_none() {
        return Ok(None);
    }
    let replay = ema_replay_ledger(config, coordinator, state_cipher, tenant_seg, previous);
    let Some(server) = ema_authorization_server(config, replay)? else {
        return Ok(None);
    };
    let state = interactive_state(
        config,
        coordinator,
        state_cipher,
        tenant_seg,
        previous.and_then(|server| server.interactive_state()),
    )?;
    let server = std::sync::Arc::new(
        server
            .with_interactive_state(state)
            .with_login_endpoints_of(previous),
    );
    discover_login_idp(&server);
    Ok(Some(server))
}

/// Read the login IdP's endpoints in the background, so a discovery
/// problem is logged when the server starts rather than at the first
/// sign-in; the first sign-in then finds them cached.
fn discover_login_idp(server: &Arc<crate::runtime::authorization_server::AuthorizationServer>) {
    if server.login_idp().is_none() || tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    let server = Arc::downgrade(server);
    tokio::spawn(async move {
        let Some(server) = server.upgrade() else {
            return;
        };
        if let Some(login) = server.login_idp() {
            // A failure is logged where it happens.
            let _ = login.metadata().await;
        }
    });
}

/// The sealed state of interactive sign-in when a trusted IdP has a
/// `login` block; `None` otherwise. `previous` is the state of the server
/// a reload replaces: its process-memory store, its open file store, the
/// key of either and its revoked set pass to the state returned.
///
/// The store is `interactive.store` as resolved against the cluster. On
/// a clustered coordinator it is the coordinator's key-value store under
/// the cluster's state encryption and tenant prefix; a coordinator that
/// exposes none refuses to start, or with `cluster.allow_degraded_boot`
/// leaves sign-in unavailable (503) rather than single-use per replica.
/// The state key is `interactive.state_keys`, else derived from the
/// cluster state key, else the file store's generated `state.key`, else a
/// key for the life of the process.
pub(crate) fn interactive_state(
    config: &AppConfig,
    coordinator: Option<&Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    state_cipher: &StateEncryption,
    tenant_seg: &Option<String>,
    previous: Option<&crate::runtime::authorization_server::InteractiveState>,
) -> Result<Option<crate::runtime::authorization_server::InteractiveState>> {
    interactive_state_under(
        config,
        coordinator,
        state_cipher,
        tenant_seg,
        previous,
        crate::config::interactive_login::default_file_store_dir,
    )
}

/// [`interactive_state`], with `default_store_dir` answering where a file
/// store without `interactive.store.dir` lives.
pub(crate) fn interactive_state_under(
    config: &AppConfig,
    coordinator: Option<&Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    state_cipher: &StateEncryption,
    tenant_seg: &Option<String>,
    previous: Option<&crate::runtime::authorization_server::InteractiveState>,
    default_store_dir: impl FnOnce() -> std::path::PathBuf,
) -> Result<Option<crate::runtime::authorization_server::InteractiveState>> {
    use crate::config::interactive_login::{
        GENERATED_STATE_KEY_FILE, ResolvedInteractiveStore, StateKeySource,
    };
    use crate::runtime::authorization_server::state::{
        FileStore, FileStoreLimits, InteractiveState, KeyringSource, StateBackend, StateKeyring,
        StateParts, UnavailableStore, memory_store,
    };
    const AT: &str = "governance.access.authorization_server.interactive";

    let Some(authz) = config.governance.access.authorization_server.as_ref() else {
        return Ok(None);
    };
    if authz.login_idp().is_none() {
        return Ok(None);
    }
    let settings = authz.interactive_settings();
    let cluster = &config.cluster;
    let source = settings.state_key_source(cluster).ok_or_else(|| {
        anyhow::anyhow!(
            "{AT}: the cluster store needs a key to seal sign-in state, stored IdP refresh tokens \
             included; set cluster.state_encryption_key_env or {AT}.state_keys"
        )
    })?;

    let mut opened_file_store = None;
    let (backend, kv): (StateBackend, Arc<dyn mcpg_cluster_api::KeyValueStore>) = match settings
        .resolved_store_under(cluster, default_store_dir)
    {
        ResolvedInteractiveStore::Cluster if !cluster.is_single_node() => {
            match coordinator.and_then(|c| c.key_value_store()) {
                Some(kv) => (
                    StateBackend::Cluster,
                    wrap_tenant_kv(wrap_state_kv(kv, state_cipher), tenant_seg),
                ),
                None if cluster.allow_degraded_boot => {
                    if previous.is_none_or(|state| state.is_available()) {
                        tracing::error!(
                            cluster_kind = %cluster.kind,
                            "the cluster coordinator exposes no key-value store: interactive \
                             sign-in answers 503 until it does (cluster.allow_degraded_boot)"
                        );
                    }
                    (
                        StateBackend::Unavailable,
                        Arc::new(UnavailableStore::new(
                            "the cluster coordinator exposes no key-value store",
                        )) as Arc<dyn mcpg_cluster_api::KeyValueStore>,
                    )
                }
                None => anyhow::bail!(
                    "interactive sign-in needs the key-value store of the cluster coordinator \
                     (cluster.kind `{}`), and it exposes none: codes and refresh tokens would be \
                     single-use per replica. Fix the coordinator, or set \
                     cluster.allow_degraded_boot: true to start with sign-in unavailable",
                    cluster.kind
                ),
            }
        }
        ResolvedInteractiveStore::Cluster | ResolvedInteractiveStore::Memory => {
            match previous.filter(|state| *state.backend() == StateBackend::InProcess) {
                Some(state) => (StateBackend::InProcess, Arc::clone(state.store())),
                None => (StateBackend::InProcess, memory_store()),
            }
        }
        ResolvedInteractiveStore::File { dir } => {
            let resolved = std::fs::canonicalize(&dir).ok();
            let open = previous.filter(|state| {
                matches!(state.backend(), StateBackend::File { dir: open }
                        if resolved.as_ref() == Some(open))
            });
            match open {
                Some(state) => (state.backend().clone(), Arc::clone(state.store())),
                None => {
                    let store =
                        FileStore::open(&dir, FileStoreLimits::default()).with_context(|| {
                            format!(
                                "{AT}.store: the sign-in file store at {} does not open; set \
                                 {AT}.store.dir (or MCPG_STATE_DIR) to a writable directory on a \
                                 persistent volume, or {AT}.store.kind: memory to keep sign-ins \
                                 in process memory",
                                dir.display()
                            )
                        })?;
                    let backend = StateBackend::File {
                        dir: store.dir().to_owned(),
                    };
                    opened_file_store = Some(store.clone());
                    (
                        backend,
                        Arc::new(store) as Arc<dyn mcpg_cluster_api::KeyValueStore>,
                    )
                }
            }
        }
    };

    let reuse_keyring = |wanted: &KeyringSource| {
        previous
            .filter(|state| state.keyring().source() == wanted)
            .map(|state| Arc::clone(state.keyring()))
    };
    let keyring = match source {
        StateKeySource::Keyring { .. } => {
            Arc::new(StateKeyring::from_config(&settings.state_keys)?)
        }
        StateKeySource::ClusterKey { ref env } => {
            let base = cluster_state_key_bytes(cluster)?.ok_or_else(|| {
                anyhow::anyhow!("cluster.state_encryption_key_env `{env}` holds no key")
            })?;
            Arc::new(StateKeyring::from_cluster_key(
                &base,
                cluster.state_encryption_key_id.as_deref(),
            )?)
        }
        StateKeySource::GeneratedFile { .. } => {
            let StateBackend::File { ref dir } = backend else {
                anyhow::bail!("{AT}: a generated state key belongs to a file store");
            };
            let path = dir.join(GENERATED_STATE_KEY_FILE);
            match reuse_keyring(&KeyringSource::File(path.clone())) {
                Some(keyring) => keyring,
                None => {
                    let (keyring, generated) = StateKeyring::from_file(&path)?;
                    if generated {
                        info!(
                            path = %path.display(),
                            "generated the state key of interactive sign-in (mode 0600); back it \
                             up with the store, whose records cannot be opened without it"
                        );
                        if let Some(records) = opened_file_store
                            .as_ref()
                            .map(FileStore::len)
                            .filter(|records| *records > 0)
                        {
                            warn!(
                                records,
                                "the sign-in store holds records sealed with a key that is gone; \
                                 they no longer open, and expire on their own"
                            );
                        }
                    }
                    Arc::new(keyring)
                }
            }
        }
        StateKeySource::Process => match reuse_keyring(&KeyringSource::Process) {
            Some(keyring) => keyring,
            None => Arc::new(StateKeyring::process()?),
        },
    };

    let state = InteractiveState::new(StateParts {
        kv,
        backend,
        keyring,
        issuer: authz.issuer.clone(),
        revoked: previous
            .map(|state| Arc::clone(state.revoked()))
            .unwrap_or_default(),
        revocation_interval: std::time::Duration::from_secs(
            settings.revocation_check_interval_secs,
        ),
    })?;
    if previous.is_none_or(|before| {
        before.backend() != state.backend() || !before.keyring().same_keys(state.keyring())
    }) {
        info!(
            store = %state.backend(),
            state_key = %source,
            "interactive sign-in state ready"
        );
    }
    Ok(Some(state))
}

/// The ledger the EMA authorization server records redeemed ID-JAGs in.
/// A clustered deployment records them in the coordinator's shared KV,
/// so an assertion is redeemed once across every replica. Otherwise the
/// ledger is in-process and taken over from `previous`, the server a
/// reload replaces: the single-node coordinator, and with it its KV, is
/// rebuilt on every reload.
pub(crate) fn ema_replay_ledger(
    config: &AppConfig,
    coordinator: Option<&Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    state_cipher: &StateEncryption,
    tenant_seg: &Option<String>,
    previous: Option<&crate::runtime::authorization_server::AuthorizationServer>,
) -> crate::runtime::authorization_server::ReplayLedger {
    use crate::runtime::authorization_server::ReplayLedger;
    if !config.cluster.is_single_node() {
        if let Some(kv) = coordinator.and_then(|c| c.key_value_store()) {
            return ReplayLedger::shared(wrap_tenant_kv(
                wrap_state_kv(kv, state_cipher),
                tenant_seg,
            ));
        }
        if per_replica_ledger_is_news(previous) {
            warn!(
                "the cluster coordinator exposes no key_value_store: single use of ID-JAGs and \
                 client assertions is enforced per replica, so each may be used once on each \
                 instance"
            );
        }
    }
    previous
        .map(|server| server.replay_ledger())
        .filter(|ledger| ledger.is_process_local())
        .cloned()
        .unwrap_or_else(ReplayLedger::in_process)
}

/// Whether a per-replica ledger is worth reporting: at boot, or when the
/// server it replaces shared one. A reload runs on every registry sync
/// pass, so reporting it on each would repeat the same warning.
pub(crate) fn per_replica_ledger_is_news(
    previous: Option<&crate::runtime::authorization_server::AuthorizationServer>,
) -> bool {
    previous.is_none_or(|server| !server.replay_ledger().is_process_local())
}

/// Build the AAuth resource role when `server.aauth_resource_metadata` is
/// configured. Public so the integration-test harness can wire it the same
/// way boot and reload do.
pub fn build_aauth_resource(
    config: &AppConfig,
) -> Result<Option<std::sync::Arc<crate::runtime::aauth_resource::AauthResource>>> {
    let Some(ref meta) = config.gateway.server.aauth_resource_metadata else {
        return Ok(None);
    };
    let resource = crate::runtime::aauth_resource::AauthResource::from_config(meta)?;
    if resource.can_mint() && !config.cluster.is_single_node() {
        tracing::warn!(
            "server.aauth_resource_metadata under a multi-node cluster: revocations and \
             person-token presentations are tracked per replica; exposure is bounded by the \
             AAuth token lifetimes (auth tokens ≤ 1 h)"
        );
    }
    info!(resource = ?resource, "AAuth resource role initialized");
    Ok(Some(std::sync::Arc::new(resource)))
}

pub(crate) fn build_oidc_resolver(
    config: &AppConfig,
) -> Result<Option<crate::runtime::oidc::OidcOAuthResolver>> {
    let oidc_config = match &config.governance.access.oidc_oauth {
        Some(c) => c,
        None => return Ok(None),
    };

    let resolver = crate::runtime::oidc::from_gateway_config(oidc_config)?;
    info!(
        resolver = ?resolver,
        "OIDC/OAuth resolver initialized"
    );
    Ok(Some(resolver))
}

/// Secret rotation: inject the deduplicated set of
/// `secret_ref` URIs the resolver expanded into `spec` under the
/// reserved `__mcpg_secret_refs` key. Plugins that subscribe to
/// rotation events read the field at `register_profile` time and
/// scope their `evict_for_secret` calls to URIs in the list (avoids
/// the eviction storm a cluster-wide unscoped fan-out would cause).
///
/// The key is private — schema validation in each plugin tolerates
/// unknown keys, and the field is stripped from any audit / config
/// serialization that traverses spec values.
pub(crate) fn inject_secret_refs_hint(
    spec: &mut serde_json::Value,
    refs: &std::collections::BTreeSet<String>,
) {
    if refs.is_empty() {
        return;
    }
    let arr: Vec<serde_json::Value> = refs
        .iter()
        .map(|s| serde_json::Value::String(s.clone()))
        .collect();
    if let Some(obj) = spec.as_object_mut() {
        obj.insert(
            "__mcpg_secret_refs".to_owned(),
            serde_json::Value::Array(arr),
        );
    }
}

#[cfg(test)]
#[path = "auth_wiring_tests.rs"]
mod tests;
