//! Boot-time configuration diagnostics.
//!
//! Warnings for configurations that parse, validate, and boot, but cannot
//! behave the way the operator meant. The trust-floor case is the reason
//! this module exists: a binding whose floor no request can clear is
//! filtered out of every `*/list` and rejected on call, and neither the
//! empty list nor the boot log says why.

use tracing::warn;

use super::{AppConfig, TrustLevelConfig};

/// The highest trust tier any request can reach under this config.
///
/// Mirrors `RequestIdentity::trust_level`: `Verified` needs an identity
/// source (embedded EMA authorization server, OIDC/OAuth, JWKS, or an
/// `identity_provider` plugin), `HeaderAsserted` additionally needs
/// `gateway.server.trust_subject_header`, and a gateway with neither can
/// only ever see anonymous callers.
pub fn reachable_trust_ceiling(config: &AppConfig) -> TrustLevelConfig {
    let access = &config.governance.access;
    let verifiable = access.jwks.is_some()
        || access.oidc_oauth.is_some()
        || access.authorization_server.is_some()
        || config
            .plugins
            .iter()
            .any(|entry| entry.class == "identity_provider");

    if verifiable {
        TrustLevelConfig::Verified
    } else if config.gateway.server.trust_subject_header {
        TrustLevelConfig::HeaderAsserted
    } else {
        TrustLevelConfig::Unauthenticated
    }
}

/// Bindings whose `governance.minimum_trust` sits above the trust ceiling
/// the identity posture can produce — each one hidden from every list and
/// rejected on call.
pub fn unreachable_trust_bindings(config: &AppConfig) -> Vec<&str> {
    let ceiling = reachable_trust_ceiling(config);
    config
        .all_bindings()
        .filter(|(_, binding)| binding.governance.minimum_trust > ceiling)
        .map(|(_, binding)| binding.name.as_str())
        .collect()
}

/// How to make an unreachable floor reachable, given what the config
/// already has.
pub fn trust_ceiling_remedy(ceiling: TrustLevelConfig) -> &'static str {
    if ceiling == TrustLevelConfig::Unauthenticated {
        "configure an identity source (governance.access.oidc_oauth / .jwks / \
         .authorization_server, or an identity_provider plugin), set \
         gateway.server.trust_subject_header to accept header-asserted identity, or lower the \
         binding's governance.minimum_trust"
    } else {
        "configure an identity source (governance.access.oidc_oauth / .jwks / \
         .authorization_server, or an identity_provider plugin), or lower the binding's \
         governance.minimum_trust"
    }
}

/// Settings that validate but leave the embedded EMA authorization server
/// (`governance.access.authorization_server`) unreachable for some clients.
/// One operator-facing message per finding; empty without the server.
pub fn access_posture_warnings(config: &AppConfig) -> Vec<String> {
    let access = &config.governance.access;
    let Some(ref authz) = access.authorization_server else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    // RFC 8414 §3.3: a client refuses metadata whose `issuer` differs from
    // the URL it was listed under, so only an exact entry is discoverable.
    let issuer = authz.issuer.as_str();
    if let Some(ref rm) = access.resource_metadata
        && !rm.authorization_servers.is_empty()
        && !rm.authorization_servers.iter().any(|s| s == issuer)
    {
        warnings.push(format!(
            "governance.access.resource_metadata.authorization_servers does not list the \
             embedded authorization server `{issuer}`, so EMA clients cannot discover it. \
             Add `{issuer}` to the list, or leave the list empty to derive it"
        ));
    }
    // RFC 8414 §2 requires https; clients POST assertions and client
    // secrets to the token endpoint the issuer names.
    if let Ok(parsed) = url::Url::parse(issuer)
        && parsed.scheme() == "http"
        && !parsed.host().is_some_and(|host| match host {
            url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        })
    {
        warnings.push(format!(
            "governance.access.authorization_server.issuer `{issuer}` is http:// on a host that \
             is not loopback: clients send ID-JAGs and client secrets to its token endpoint in \
             the clear, and RFC 8414 requires an https issuer. Serve the gateway over https and \
             set the issuer to its https:// origin"
        ));
    }
    if let Some(ref resource) = authz.resource
        && let Some(ref rm) = access.resource_metadata
        && !rm
            .resources()
            .any(|advertised| advertised.trim_end_matches('/') == resource.trim_end_matches('/'))
    {
        warnings.push(format!(
            "governance.access.authorization_server.resource `{resource}` is not a resource \
             identifier governance.access.resource_metadata advertises ({}): an ID-JAG that \
             names no resource gets a token for an audience no client was told about. Remove \
             the key to mint for resource_metadata.resource, or set it to one of the advertised \
             identifiers",
            rm.resources().collect::<Vec<_>>().join(", ")
        ));
    }
    if !access.require_authentication {
        warnings.push(
            "governance.access.authorization_server is set but \
             governance.access.require_authentication is false: an anonymous initialize and \
             */list succeed, so an EMA client that authenticates only after a 401 never \
             starts the flow. Set require_authentication: true unless anonymous access is \
             intended"
                .to_owned(),
        );
    }
    // The metadata and token endpoints are served by this gateway, so the
    // issuer origin must route here like one of the resource origins.
    if let Some(ref rm) = access.resource_metadata
        && let Some(issuer_origin) = url_origin(issuer)
    {
        let resource_origins: Vec<String> = rm.resources().filter_map(url_origin).collect();
        if !resource_origins.is_empty() && !resource_origins.contains(&issuer_origin) {
            warnings.push(format!(
                "governance.access.authorization_server.issuer is on origin {issuer_origin}, \
                 but the protected resource is served at {}: clients fetch the authorization \
                 server metadata and POST to /oauth/token on the issuer origin, so it must \
                 reach this gateway. Set the issuer to {} unless that origin routes here too",
                resource_origins.join(", "),
                resource_origins[0]
            ));
        }
    }
    // Advertised support that no client can use still steers clients such
    // as Claude to identify with a document, which is then refused.
    let documents = &authz.client_id_metadata_documents;
    if authz.client_id_metadata_documents_enabled()
        && documents.allowed_hosts.is_empty()
        && !authz
            .clients
            .iter()
            .any(|client| super::access::client_id_is_url(&client.client_id, false))
    {
        warnings.push(
            "governance.access.authorization_server.client_id_metadata_documents is enabled, \
             but no clients[].client_id is a metadata document URL and allowed_hosts is empty, \
             so every client that identifies with a document is refused. Register the \
             document URL under clients[], list its host under allowed_hosts, or set enabled: \
             false"
                .to_owned(),
        );
    }
    // An OIDC provider reports its configured issuer verbatim, so only an
    // exact match joins the two ways in. Without `oidc_oauth` the SSO
    // provider may be a plugin whose configuration is not read here.
    if let Some(ref oidc) = access.oidc_oauth {
        for idp in &authz.trusted_idps {
            if let Some(ref principal) = idp.principal_issuer
                && !oidc.providers.iter().any(|p| &p.issuer == principal)
            {
                warnings.push(format!(
                    "governance.access.authorization_server.trusted_idps[`{}`].principal_issuer \
                     `{principal}` is not the issuer of any governance.access.oidc_oauth provider, \
                     so this IdP's EMA callers share no principal with an SSO user. Set it to the \
                     provider's issuer exactly as written there",
                    idp.issuer
                ));
            }
        }
    }
    if authz.access_token_ttl_secs > super::access::ACCESS_TOKEN_TTL_WARN_SECS {
        warnings.push(format!(
            "governance.access.authorization_server.access_token_ttl_secs is {}: a minted \
             token cannot be revoked, so it stays valid that long after the enterprise IdP \
             revokes the user. Keep it at {} or below unless the IdP's ID-JAG quota needs \
             longer-lived tokens",
            authz.access_token_ttl_secs,
            super::access::ACCESS_TOKEN_TTL_WARN_SECS
        ));
    }
    warnings.extend(interactive_login_warnings(config, authz));
    warnings
}

/// Settings that validate but leave interactive sign-in, or the
/// federations that use the stored IdP sign-in, working less well than the
/// operator likely meant. Empty without a `trusted_idps[].login` block.
fn interactive_login_warnings(
    config: &AppConfig,
    authz: &super::AuthorizationServerConfig,
) -> Vec<String> {
    use super::interactive_login::{
        LoopbackHost, RedirectUriKind, ResolvedInteractiveStore, idp_subject_token_users,
        redirect_uri_kind,
    };
    let Some((idp, login)) = authz.login_idp() else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    let issuer = authz.issuer.as_str();
    let at = format!(
        "governance.access.authorization_server.trusted_idps[`{}`].login",
        idp.issuer
    );
    // Clients follow the first listed authorization server.
    if let Some(ref rm) = config.governance.access.resource_metadata
        && rm.authorization_servers.iter().any(|s| s == issuer)
        && rm.authorization_servers.first().map(String::as_str) != Some(issuer)
    {
        warnings.push(format!(
            "governance.access.resource_metadata.authorization_servers lists the embedded \
             authorization server `{issuer}`, but not first: MCP clients sign in at the first \
             entry, so they skip interactive sign-in here. List `{issuer}` first, or leave the \
             list empty to derive it"
        ));
    }
    let idp_users = idp_subject_token_users(config);
    if !idp_users.is_empty() && idp.issuer.contains("/oauth2/") {
        warnings.push(format!(
            "{at}: the IdP issuer `{}` is an Okta custom authorization server, which issues no \
             ID-JAGs, so the federations that present the stored sign-in ({}) fail. Use the org \
             authorization server, `https://{{org}}.okta.com`",
            idp.issuer,
            idp_users
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for (path, auth) in &idp_users {
        warnings.extend(issuer_provider_mismatches(config, login, path, auth));
    }
    if !login.scopes.iter().any(|s| s == "offline_access") {
        warnings.push(format!(
            "{at}.scopes lacks `offline_access`, so the IdP issues no refresh token: clients get \
             no gateway refresh token while refresh_tokens.revalidate_with_idp is on, and \
             idp_refresh_token federations cannot work"
        ));
    }
    if let Some(ref canonical) = config.gateway.server.canonical_url
        && let (Some(canonical_origin), Some(issuer_origin)) =
            (url_origin(canonical), url_origin(issuer))
        && canonical_origin != issuer_origin
    {
        warnings.push(format!(
            "gateway.server.canonical_url is on origin {canonical_origin}, but the embedded \
             authorization server is {issuer_origin}: every other host redirects to the \
             canonical one, so the sign-in pages and the IdP callback on the issuer origin are \
             never reached. Set both to the same origin"
        ));
    }
    let settings = authz.interactive_settings();
    let in_memory = match settings.resolved_store(&config.cluster) {
        ResolvedInteractiveStore::Memory => true,
        ResolvedInteractiveStore::Cluster => config.cluster.is_single_node(),
        ResolvedInteractiveStore::File { .. } => false,
    };
    if in_memory {
        warnings.push(
            "governance.access.authorization_server.interactive.store keeps sign-in state in \
             process memory on a single node: every restart signs every user out and drops the \
             stored IdP sign-ins. Remove store to keep them in the default file store"
                .to_owned(),
        );
    }
    for client in &authz.clients {
        for uri in &client.redirect_uris {
            if redirect_uri_kind(uri) == Ok(RedirectUriKind::Loopback(LoopbackHost::Localhost)) {
                warnings.push(format!(
                    "governance.access.authorization_server.clients[`{}`].redirect_uris entry \
                     `{uri}` names `localhost`, which can resolve to another address (RFC 8252 \
                     §8.3). Prefer http://127.0.0.1 or http://[::1] if the client allows it",
                    client.client_id
                ));
            }
        }
    }
    warnings
}

/// How the credential issuer behind one `idp_*` federation disagrees with
/// the login client, when it is `oauth-id-jag` or `oauth-token-exchange`:
/// the stored sign-in may only be exchanged at the token endpoint that
/// issued it, by the client it was issued to, so each call would be
/// refused.
fn issuer_provider_mismatches(
    config: &AppConfig,
    login: &super::TrustedIdpLoginConfig,
    path: &str,
    auth: &super::federation::AuthConfig,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some((plugin, target)) = auth
        .credential
        .as_deref()
        .and_then(|cred| cred.strip_prefix("cred://"))
        .and_then(|rest| rest.split_once('/'))
    else {
        return warnings;
    };
    let target = target.split('#').next().unwrap_or(target);
    let Some(entry) = config.plugins.iter().find(|entry| entry.id == plugin) else {
        return warnings;
    };
    let manifest = entry.r#ref.as_deref().unwrap_or(entry.id.as_str());
    let token_url_key = match manifest.strip_prefix("dev.mcpg.").unwrap_or(manifest) {
        "credential.oauth-id-jag" => "idp_token_url",
        "credential.oauth-token-exchange" => "token_url",
        _ => return warnings,
    };
    let Some(provider) = entry
        .config
        .get("providers")
        .and_then(|providers| providers.get(target))
        .or_else(|| entry.config.get("target_template"))
    else {
        return warnings;
    };
    let resolved = |value: &str| !value.contains("${");
    if let Some(client_id) = provider.get("client_id").and_then(|v| v.as_str())
        && resolved(client_id)
        && resolved(&login.client_id)
        && client_id != login.client_id
    {
        warnings.push(format!(
            "{path} presents the stored IdP sign-in through plugin `{plugin}` provider \
             `{target}`, whose client_id `{client_id}` is not the login client `{}`: the IdP \
             binds the sign-in to the client it was issued to, so every exchange is refused. \
             Use the login client for the issuer",
            login.client_id
        ));
    }
    if let (Some(token_url), Some(endpoint)) = (
        provider.get(token_url_key).and_then(|v| v.as_str()),
        login.token_endpoint.as_deref(),
    ) && resolved(token_url)
        && resolved(endpoint)
        && token_url != endpoint
    {
        warnings.push(format!(
            "{path} presents the stored IdP sign-in through plugin `{plugin}` provider \
             `{target}`, whose {token_url_key} `{token_url}` is not the login token_endpoint \
             `{endpoint}`: the stored sign-in may only be exchanged where it was issued, so \
             every exchange is refused"
        ));
    }
    warnings
}

/// `scheme://host[:port]` of an absolute `http(s)` URL, lowercased, with
/// the scheme's default port dropped.
fn url_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    })
}

/// Boot-side counterpart to [`access_posture_warnings`].
pub fn warn_access_posture(config: &AppConfig) {
    for warning in access_posture_warnings(config) {
        warn!("{warning}");
    }
}

/// Boot-side counterpart to [`unreachable_trust_bindings`].
pub fn warn_unreachable_binding_trust(config: &AppConfig) {
    let unreachable = unreachable_trust_bindings(config);
    if unreachable.is_empty() {
        return;
    }
    let ceiling = reachable_trust_ceiling(config);
    warn!(
        bindings = %unreachable.join(", "),
        trust_ceiling = ?ceiling,
        "binding trust floor is unreachable: these capabilities are hidden from every \
         list and rejected on call because no request can reach their \
         governance.minimum_trust — {}",
        trust_ceiling_remedy(ceiling)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parsed rather than constructed so the serde defaults under test
    /// (notably the per-binding trust floor) are the real ones.
    fn config(yaml: &str) -> AppConfig {
        serde_yaml::from_str(yaml).expect("test config parses")
    }

    fn unreachable(config: &AppConfig) -> Vec<&str> {
        let ceiling = reachable_trust_ceiling(config);
        config
            .all_bindings()
            .filter(|(_, b)| b.governance.minimum_trust > ceiling)
            .map(|(_, b)| b.name.as_str())
            .collect()
    }

    const ANONYMOUS_QUICKSTART: &str = r#"
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        backend:
          kind: mock
          response: { ok: true }
"#;

    #[test]
    fn ceiling_is_unauthenticated_without_identity_or_header_trust() {
        assert_eq!(
            reachable_trust_ceiling(&config(ANONYMOUS_QUICKSTART)),
            TrustLevelConfig::Unauthenticated
        );
    }

    #[test]
    fn trust_subject_header_lifts_ceiling_to_header_asserted() {
        let config = config(
            r#"
gateway:
  server:
    trust_subject_header: true
"#,
        );
        assert_eq!(
            reachable_trust_ceiling(&config),
            TrustLevelConfig::HeaderAsserted
        );
    }

    #[test]
    fn identity_provider_plugin_lifts_ceiling_to_verified() {
        let config = config(
            r#"
plugins:
  - id: dev.mcpg.identity.oidc
    class: identity_provider
    source:
      path: /nonexistent/oidc.so
"#,
        );
        assert_eq!(reachable_trust_ceiling(&config), TrustLevelConfig::Verified);
    }

    #[test]
    fn jwks_lifts_ceiling_to_verified() {
        let config = config(
            r#"
governance:
  access:
    jwks:
      url: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com/
      audience: mcpg
"#,
        );
        assert_eq!(reachable_trust_ceiling(&config), TrustLevelConfig::Verified);
    }

    /// The quickstart shape: anonymous posture, binding left on the
    /// default floor. Catching exactly this is why the module exists.
    #[test]
    fn default_binding_floor_is_unreachable_when_anonymous() {
        assert_eq!(
            unreachable(&config(ANONYMOUS_QUICKSTART)),
            vec!["dev.mock.echo"],
            "the default binding floor must be flagged under an anonymous posture"
        );
    }

    #[test]
    fn explicit_unauthenticated_floor_is_reachable_when_anonymous() {
        let config = config(
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
          response: { ok: true }
"#,
        );
        assert!(
            unreachable(&config).is_empty(),
            "an unauthenticated floor is always reachable"
        );
    }

    const EMA_ACCESS: &str = r#"
governance:
  access:
    resource_metadata:
      resource: https://mcp.example.com/mcp
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: ema-signing-secret-0123456789abcdef
      trusted_idps:
        - issuer: https://acme.okta.com
      clients:
        - client_id: mcp-client
"#;

    #[test]
    fn no_access_posture_warning_without_an_authorization_server() {
        assert!(access_posture_warnings(&config(ANONYMOUS_QUICKSTART)).is_empty());
    }

    /// An EMA gateway that serves anonymous `initialize` never hands a
    /// lazy-auth client the 401 it starts from.
    #[test]
    fn authorization_server_without_require_authentication_warns() {
        let warnings = access_posture_warnings(&config(EMA_ACCESS));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("require_authentication"));

        let mut strict = config(EMA_ACCESS);
        strict.governance.access.require_authentication = true;
        assert!(access_posture_warnings(&strict).is_empty());
    }

    /// An explicit `authorization_servers` list is published as written:
    /// one that omits the embedded issuer, or names it with a trailing
    /// slash, hides it from RFC 8414 clients. An empty list derives it.
    #[test]
    fn explicit_authorization_servers_must_name_the_embedded_issuer() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        let listed = |cfg: &mut AppConfig, servers: &[&str]| {
            cfg.governance
                .access
                .resource_metadata
                .as_mut()
                .expect("resource_metadata")
                .authorization_servers = servers.iter().map(|s| (*s).to_owned()).collect();
            access_posture_warnings(cfg)
        };

        let omitted = listed(&mut cfg, &["https://acme.okta.com"]);
        assert_eq!(omitted.len(), 1, "{omitted:?}");
        assert!(omitted[0].contains("`https://mcp.example.com`"));

        assert_eq!(
            listed(&mut cfg, &["https://mcp.example.com/"]).len(),
            1,
            "a trailing slash is a different issuer identifier"
        );
        assert!(
            listed(
                &mut cfg,
                &["https://acme.okta.com", "https://mcp.example.com"]
            )
            .is_empty()
        );
        assert!(listed(&mut cfg, &[]).is_empty());
    }

    /// Minted tokens cannot be revoked; a lifetime past an hour is allowed
    /// but called out.
    #[test]
    fn long_access_token_ttl_warns() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        let authz = cfg
            .governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server");
        authz.access_token_ttl_secs = 3600;
        assert!(access_posture_warnings(&cfg).is_empty());

        cfg.governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server")
            .access_token_ttl_secs = 7200;
        let warnings = access_posture_warnings(&cfg);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("access_token_ttl_secs is 7200"));
    }

    /// Metadata documents advertised with nothing that admits one: every
    /// client that follows the advertisement is refused.
    #[test]
    fn metadata_documents_no_client_can_use_warn() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        let authz = cfg
            .governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server");
        authz.client_id_metadata_documents.enabled = Some(true);
        let warnings = access_posture_warnings(&cfg);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("client_id_metadata_documents"));

        let authz = cfg
            .governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server");
        authz.client_id_metadata_documents.allowed_hosts = vec!["claude.ai".to_owned()];
        assert!(access_posture_warnings(&cfg).is_empty());

        // The default follows the registered clients, so it never warns.
        let authz = cfg
            .governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server");
        authz.client_id_metadata_documents = Default::default();
        assert!(access_posture_warnings(&cfg).is_empty());
    }

    /// The token endpoint lives on the issuer origin, so an issuer no
    /// resource origin shares is likely one that does not reach the
    /// gateway. A custom-domain resource does not count against a
    /// canonical-origin issuer.
    #[test]
    fn issuer_origin_outside_the_resource_origins_warns() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        cfg.governance
            .access
            .resource_metadata
            .as_mut()
            .expect("resource_metadata")
            .additional_resources = vec!["https://mcp.acme.example/mcp".to_owned()];
        assert!(access_posture_warnings(&cfg).is_empty());

        cfg.governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server")
            .issuer = "https://auth.example.com".to_owned();
        let warnings = access_posture_warnings(&cfg);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("origin https://auth.example.com")
                && warnings[0].contains("https://mcp.example.com, https://mcp.acme.example"),
            "{}",
            warnings[0]
        );
    }

    /// An issuer that ends in `/` is its own identifier: an explicit
    /// `authorization_servers` list names it with the slash.
    #[test]
    fn a_trailing_slash_issuer_is_listed_exactly() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        cfg.governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server")
            .issuer = "https://mcp.example.com/".to_owned();
        let rm = cfg
            .governance
            .access
            .resource_metadata
            .as_mut()
            .expect("resource_metadata");
        rm.authorization_servers = vec!["https://mcp.example.com/".to_owned()];
        assert!(access_posture_warnings(&cfg).is_empty());

        cfg.governance
            .access
            .resource_metadata
            .as_mut()
            .expect("resource_metadata")
            .authorization_servers = vec!["https://mcp.example.com".to_owned()];
        assert_eq!(access_posture_warnings(&cfg).len(), 1);
    }

    /// Clients send assertions and client secrets to the token endpoint,
    /// so an http issuer is called out, except on loopback.
    #[test]
    fn an_http_issuer_off_loopback_warns() {
        let with_issuer = |issuer: &str, resource: &str| {
            let mut cfg = config(EMA_ACCESS);
            cfg.governance.access.require_authentication = true;
            let rm = cfg
                .governance
                .access
                .resource_metadata
                .as_mut()
                .expect("resource_metadata");
            rm.resource = resource.to_owned();
            rm.allow_loopback_resource = true;
            cfg.governance
                .access
                .authorization_server
                .as_mut()
                .expect("authorization_server")
                .issuer = issuer.to_owned();
            access_posture_warnings(&cfg)
        };
        let warnings = with_issuer("http://mcp.example.com", "http://mcp.example.com/mcp");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("http://") && warnings[0].contains("https"),
            "{}",
            warnings[0]
        );
        for loopback in ["http://localhost:8080", "http://127.0.0.1:8080"] {
            assert!(
                with_issuer(loopback, &format!("{loopback}/mcp")).is_empty(),
                "{loopback}"
            );
        }
    }

    /// `authorization_server.resource` is the audience of every token an
    /// ID-JAG without a `resource` claim gets, so one the PRM does not
    /// advertise is called out; a trailing `/` does not count.
    #[test]
    fn an_unadvertised_default_resource_warns() {
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        let set_resource = |cfg: &mut AppConfig, resource: &str| {
            cfg.governance
                .access
                .authorization_server
                .as_mut()
                .expect("authorization_server")
                .resource = Some(resource.to_owned());
            access_posture_warnings(cfg)
        };
        assert!(set_resource(&mut cfg, "https://mcp.example.com/mcp/").is_empty());
        let warnings = set_resource(&mut cfg, "https://mcp.example.com/other");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("https://mcp.example.com/other")
                && warnings[0].contains("https://mcp.example.com/mcp"),
            "{}",
            warnings[0]
        );
    }

    /// An OIDC provider reports its issuer as written, so a principal
    /// alias that differs from every `oidc_oauth` issuer, even by a
    /// trailing slash, joins no SSO user. Without `oidc_oauth` the SSO
    /// provider may be a plugin, which is not checked.
    #[test]
    fn principal_issuer_outside_the_oidc_providers_warns() {
        const SSO: &str = "https://acme.okta.com/oauth2/default";
        let mut cfg = config(EMA_ACCESS);
        cfg.governance.access.require_authentication = true;
        cfg.governance
            .access
            .authorization_server
            .as_mut()
            .expect("authorization_server")
            .trusted_idps[0]
            .principal_issuer = Some(SSO.to_owned());
        assert!(access_posture_warnings(&cfg).is_empty());

        let sso_provider = |issuer: &str| {
            serde_json::from_value(serde_json::json!({
                "providers": [{
                    "issuer": issuer,
                    "audiences": ["https://mcp.example.com/mcp"],
                    "verification": { "kind": "oidc_jwks" },
                }]
            }))
            .expect("OIDC config parses")
        };
        cfg.governance.access.oidc_oauth = Some(sso_provider(&format!("{SSO}/")));
        let warnings = access_posture_warnings(&cfg);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("principal_issuer") && warnings[0].contains(SSO),
            "{}",
            warnings[0]
        );

        cfg.governance.access.oidc_oauth = Some(sso_provider(SSO));
        assert!(access_posture_warnings(&cfg).is_empty());
    }

    #[test]
    fn default_floor_is_reachable_once_header_trust_is_on() {
        let config = config(
            r#"
gateway:
  server:
    trust_subject_header: true
mcp:
  capabilities:
    tools:
      - name: dev.mock.echo
        description: echo
        backend:
          kind: mock
          response: { ok: true }
"#,
        );
        assert!(unreachable(&config).is_empty());
    }
}
