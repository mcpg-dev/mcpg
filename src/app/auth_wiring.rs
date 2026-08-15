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
/// `governance.access.authorization_server` is configured. The default
/// resource identifier falls back to the PRM `resource` so minted-token
/// audiences line up with what the gateway publishes. Public so the
/// integration-test harness can wire the same server its hand-built
/// runtime would otherwise lack.
pub fn build_ema_authorization_server(
    config: &AppConfig,
) -> Result<Option<std::sync::Arc<crate::runtime::authorization_server::AuthorizationServer>>> {
    let Some(ref authz_config) = config.governance.access.authorization_server else {
        return Ok(None);
    };
    let prm_resource = config
        .governance
        .access
        .resource_metadata
        .as_ref()
        .map(|rm| rm.resource.as_str());
    let server = crate::runtime::authorization_server::AuthorizationServer::from_config(
        authz_config,
        prm_resource,
    )?;
    // ID-JAG single-use is enforced from a process-local cache, so each
    // replica admits a given assertion once. Multi-replica deployments get
    // per-replica rather than cluster-wide single-use until the cache is
    // backed by the coordinator's KV.
    if authz_config.enforce_single_use && !config.cluster.is_single_node() {
        tracing::warn!(
            "governance.access.authorization_server.enforce_single_use is enabled under a \
             multi-node cluster: ID-JAG replay is detected per replica, so an assertion may be \
             redeemed once on each instance"
        );
    }
    info!(server = ?server, "EMA authorization server initialized");
    Ok(Some(std::sync::Arc::new(server)))
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
