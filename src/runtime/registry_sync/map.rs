//! Registry entry → synthesized [`FederationConfig`].
//!
//! Every synthesized federation is treated as untrusted input: the
//! registry decides which servers exist, the operator's per-registry
//! `defaults` decide how much they are trusted, and the gateway's
//! default-deny rails (no stdio, no insecure HTTP, SSRF guard, no
//! tunnels) are not reachable from registry data at all.

use std::collections::BTreeMap;

use crate::config::UpstreamTransport;
use crate::config::federation::{
    FederationConfig, FilterConfig, NamingConfig, ResponseConfig, SessionConfig, UpstreamConfig,
    UpstreamSafetyConfig,
};
use crate::config::registry::{McpRegistryConfig, OnDeprecated, RegistryServerOverride};

use super::client::{EntryStatus, RegistryEntry, RemoteJson};

/// Why an entry was not federated. Skips are per-entry and reported —
/// one bad entry never fails a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkipReason {
    /// Tombstoned in the registry.
    Deleted,
    /// Deprecated and the registry's policy excludes deprecated servers.
    Deprecated,
    /// Filtered out (include/exclude globs, namespace allowlist,
    /// `enabled: false`, or a non-latest version).
    Filtered,
    /// No `streamable-http` remote to connect to (packages-only entries
    /// land here too — installables are a provisioning concern, not an
    /// auto-federation one).
    NoUsableRemote,
    /// A required URL variable or request header has no configured
    /// value (names carried for the status report).
    MissingInput(String),
    /// The synthesized federation failed validation.
    Invalid(String),
}

impl SkipReason {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::Deprecated => "deprecated",
            Self::Filtered => "filtered",
            Self::NoUsableRemote => "no_usable_remote",
            Self::MissingInput(_) => "missing_input",
            Self::Invalid(_) => "invalid",
        }
    }
}

/// Map one registry entry to a federation, or a reason it was skipped.
/// `deprecated` entries that federate under `serve_and_warn` are
/// reported by the caller (the mapping itself is unchanged).
pub(crate) fn federation_for_entry(
    registry: &McpRegistryConfig,
    entry: &RegistryEntry,
) -> Result<FederationConfig, SkipReason> {
    match entry.status {
        EntryStatus::Deleted => return Err(SkipReason::Deleted),
        EntryStatus::Deprecated => {
            if matches!(registry.on_deprecated, OnDeprecated::Exclude) {
                return Err(SkipReason::Deprecated);
            }
        }
        EntryStatus::Active => {}
    }
    if !entry.is_latest {
        return Err(SkipReason::Filtered);
    }
    let server_name = entry.server.name.as_str();
    if !name_admitted(registry, server_name) {
        return Err(SkipReason::Filtered);
    }
    let default_override = RegistryServerOverride::default();
    let overrides = registry
        .servers
        .get(server_name)
        .unwrap_or(&default_override);
    if !overrides.enabled {
        return Err(SkipReason::Filtered);
    }

    let remote = entry
        .server
        .remotes
        .iter()
        .find(|r| r.kind == "streamable-http")
        .ok_or(SkipReason::NoUsableRemote)?;
    let url = resolve_remote_url(remote, overrides)?;
    // `tunnel://` is a third accepted upstream scheme that requires no safety
    // opt-in — it bypasses the https requirement and the private-backend gate
    // that the rails below pin. Registry data must not be able to select it.
    if url.starts_with("tunnel://") {
        return Err(SkipReason::NoUsableRemote);
    }
    let headers = resolve_remote_headers(remote, overrides)?;

    // `{server}` in the upstream credential target expands to the registry
    // server name, so one issuer block (with a target template / allowlist)
    // serves the whole registry:
    //   credential: cred://dev.mcpg.credential.oauth-id-jag/{server}
    let mut auth = overrides
        .auth
        .clone()
        .unwrap_or_else(|| registry.defaults.auth.clone());
    if let Some(cred) = auth.credential.as_mut() {
        *cred = cred.replace("{server}", server_name);
    }

    let fed = FederationConfig {
        name: federation_name(&registry.name, server_name),
        governance: registry.defaults.governance.clone(),
        retry: None,
        upstream: UpstreamConfig {
            url,
            transport: UpstreamTransport::StreamableHttp,
            // server.json carries no MCP revision — the wire adapter's
            // connect probe detects it per server.
            protocol_version: crate::config::UpstreamProtocolVersion::Auto,
            command: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            auth,
            headers,
            // The registry cannot relax transport security: stdio and
            // insecure HTTP stay denied; private backends are the
            // operator's per-registry opt-in.
            upstream_safety: UpstreamSafetyConfig {
                allow_private_backends: registry.defaults.upstream_safety.allow_private_backends,
                allow_insecure_http: false,
                allow_stdio: false,
            },
        },
        import: registry.defaults.import.clone(),
        naming: naming_for(server_name),
        filter: FilterConfig::default(),
        cache: registry.defaults.cache.clone(),
        synthesize: registry.defaults.synthesize.clone(),
        session: SessionConfig::default(),
        response: ResponseConfig::default(),
    };
    fed.validate()
        .map_err(|e| SkipReason::Invalid(e.to_string()))?;
    Ok(fed)
}

/// Whether the registry's filters admit this server name.
fn name_admitted(registry: &McpRegistryConfig, server_name: &str) -> bool {
    if !registry.filter.namespaces.is_empty() {
        let namespace = server_name.split('/').next().unwrap_or_default();
        if !registry.filter.namespaces.iter().any(|n| n == namespace) {
            return false;
        }
    }
    if registry
        .filter
        .exclude
        .iter()
        .any(|p| glob_match(p, server_name))
    {
        return false;
    }
    registry
        .filter
        .include
        .iter()
        .any(|p| glob_match(p, server_name))
}

/// Minimal glob, matching the federation filter's semantics: exact
/// match, `*` (all), or a single trailing-`*` prefix glob.
fn glob_match(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

/// Synthesized federation name: registry-scoped so two registries can
/// list the same server, with the registry name's charset already
/// restricted at validation (`--` cannot appear in it).
pub(crate) fn federation_name(registry_name: &str, server_name: &str) -> String {
    format!("{}--{}", registry_name, server_name.replace('/', "--"))
}

/// Per-server prefixes derived from the (registry-unique) server name.
/// Always non-empty: federating many servers requires distinct
/// prefixes, and the reverse-DNS server name is the natural namespace.
fn naming_for(server_name: &str) -> NamingConfig {
    let dotted = server_name.replace('/', ".");
    NamingConfig {
        tool_prefix: Some(format!("{dotted}.")),
        resource_uri_prefix: Some(format!("mcp://{dotted}/")),
        prompt_prefix: Some(format!("{dotted}.")),
    }
}

/// Substitute `{variable}` templates in the remote URL from the
/// operator's per-server values, then the registry-provided
/// value/default. Any unresolved `{...}` token skips the server — a
/// templated URL cannot be dialed literally.
fn resolve_remote_url(
    remote: &RemoteJson,
    overrides: &RegistryServerOverride,
) -> Result<String, SkipReason> {
    let mut url = remote.url.clone();
    for (name, input) in &remote.variables {
        let token = format!("{{{name}}}");
        if !url.contains(&token) {
            continue;
        }
        let value = overrides
            .variables
            .get(name)
            .map(String::as_str)
            .or_else(|| input.provided());
        match value {
            Some(value) => url = url.replace(&token, value),
            None => return Err(SkipReason::MissingInput(format!("variable `{name}`"))),
        }
    }
    if let (Some(open), true) = (url.find('{'), url.contains('}')) {
        let tail: String = url[open..].chars().take(32).collect();
        return Err(SkipReason::MissingInput(format!(
            "undeclared URL variable near `{tail}`"
        )));
    }
    Ok(url)
}

/// Resolve the remote's declared request headers: operator override
/// wins, then the registry-provided value/default. A required header
/// without a value skips the server (secrets are never guessed).
fn resolve_remote_headers(
    remote: &RemoteJson,
    overrides: &RegistryServerOverride,
) -> Result<BTreeMap<String, String>, SkipReason> {
    let mut headers = BTreeMap::new();
    for header in &remote.headers {
        let Some(name) = header.name.as_deref().filter(|n| !n.is_empty()) else {
            continue;
        };
        let value = overrides
            .headers
            .get(name)
            .map(String::as_str)
            .or_else(|| header.provided());
        match value {
            Some(value) => {
                headers.insert(name.to_owned(), value.to_owned());
            }
            None if header.is_required => {
                return Err(SkipReason::MissingInput(format!("header `{name}`")));
            }
            None => {}
        }
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::super::client::{InputJson, ServerJson};
    use super::*;

    fn registry(yaml: &str) -> McpRegistryConfig {
        serde_yaml::from_str(yaml).expect("parse registry config")
    }

    fn entry(name: &str, remotes: Vec<RemoteJson>) -> RegistryEntry {
        RegistryEntry {
            server: ServerJson {
                name: name.to_owned(),
                description: None,
                title: None,
                version: Some("1.0.0".to_owned()),
                remotes,
                packages: Vec::new(),
            },
            status: EntryStatus::Active,
            is_latest: true,
            updated_at: None,
        }
    }

    fn http_remote(url: &str) -> RemoteJson {
        RemoteJson {
            kind: "streamable-http".to_owned(),
            url: url.to_owned(),
            headers: Vec::new(),
            variables: BTreeMap::new(),
        }
    }

    #[test]
    fn maps_a_plain_remote_with_derived_names() {
        let reg = registry("name: acme\nurl: \"https://r.example\"\n");
        let fed = federation_for_entry(
            &reg,
            &entry(
                "com.acme/crm",
                vec![http_remote("https://crm.acme.example/mcp")],
            ),
        )
        .expect("federates");
        assert_eq!(fed.name, "acme--com.acme--crm");
        assert_eq!(fed.tool_prefix(), "com.acme.crm.");
        assert_eq!(
            fed.naming.resource_uri_prefix.as_deref(),
            Some("mcp://com.acme.crm/")
        );
        assert_eq!(fed.upstream.url, "https://crm.acme.example/mcp");
        assert!(fed.upstream.protocol_version.is_auto());
        assert!(!fed.upstream.upstream_safety.allow_stdio);
        assert!(!fed.upstream.upstream_safety.allow_insecure_http);
        assert!(fed.import.tools && fed.import.resources && fed.import.prompts);
    }

    #[test]
    fn credential_target_expands_server_placeholder() {
        let reg = registry(
            "name: acme\nurl: \"https://r.example\"\ndefaults:\n  auth:\n    mode: oauth_impersonation\n    credential: \"cred://dev.mcpg.credential.oauth-id-jag/{server}\"\n",
        );
        let fed = federation_for_entry(
            &reg,
            &entry(
                "com.acme/crm",
                vec![http_remote("https://crm.acme.example/mcp")],
            ),
        )
        .expect("federates");
        assert_eq!(
            fed.upstream.auth.credential.as_deref(),
            Some("cred://dev.mcpg.credential.oauth-id-jag/com.acme/crm")
        );

        // Per-server override auth expands too (expansion follows selection).
        let reg = registry(
            "name: acme\nurl: \"https://r.example\"\nservers:\n  \"com.acme/crm\":\n    auth:\n      mode: oauth_client_credentials\n      credential: \"cred://dev.mcpg.credential.oauth-client-credentials/{server}\"\n",
        );
        let fed = federation_for_entry(
            &reg,
            &entry(
                "com.acme/crm",
                vec![http_remote("https://crm.acme.example/mcp")],
            ),
        )
        .expect("federates");
        assert_eq!(
            fed.upstream.auth.credential.as_deref(),
            Some("cred://dev.mcpg.credential.oauth-client-credentials/com.acme/crm")
        );
    }

    #[test]
    fn packages_only_and_sse_only_entries_are_not_federated() {
        let reg = registry("name: acme\nurl: \"https://r.example\"\n");
        let mut packages_only = entry("com.acme/local", Vec::new());
        packages_only.server.packages = vec![serde_json::json!({"registryType": "npm"})];
        assert_eq!(
            federation_for_entry(&reg, &packages_only).unwrap_err(),
            SkipReason::NoUsableRemote
        );

        let sse_only = entry(
            "com.acme/old",
            vec![RemoteJson {
                kind: "sse".to_owned(),
                url: "https://old.acme.example/sse".to_owned(),
                headers: Vec::new(),
                variables: BTreeMap::new(),
            }],
        );
        assert_eq!(
            federation_for_entry(&reg, &sse_only).unwrap_err(),
            SkipReason::NoUsableRemote
        );
    }

    #[test]
    fn lifecycle_and_filters_gate_entries() {
        let reg = registry(
            "name: acme\nurl: \"https://r.example\"\nfilter:\n  namespaces: [com.acme]\n  exclude: [\"com.acme/experimental-*\"]\n",
        );
        let mut deleted = entry("com.acme/x", vec![http_remote("https://x.example/mcp")]);
        deleted.status = EntryStatus::Deleted;
        assert_eq!(
            federation_for_entry(&reg, &deleted).unwrap_err(),
            SkipReason::Deleted
        );

        let foreign = entry(
            "io.github.someone/y",
            vec![http_remote("https://y.example/mcp")],
        );
        assert_eq!(
            federation_for_entry(&reg, &foreign).unwrap_err(),
            SkipReason::Filtered
        );

        let excluded = entry(
            "com.acme/experimental-z",
            vec![http_remote("https://z.example/mcp")],
        );
        assert_eq!(
            federation_for_entry(&reg, &excluded).unwrap_err(),
            SkipReason::Filtered
        );

        let exclude_deprecated =
            registry("name: acme\nurl: \"https://r.example\"\non_deprecated: exclude\n");
        let mut deprecated = entry("com.acme/w", vec![http_remote("https://w.example/mcp")]);
        deprecated.status = EntryStatus::Deprecated;
        assert_eq!(
            federation_for_entry(&exclude_deprecated, &deprecated).unwrap_err(),
            SkipReason::Deprecated
        );
        let serve_and_warn = registry("name: acme\nurl: \"https://r.example\"\n");
        federation_for_entry(&serve_and_warn, &deprecated).expect("served under serve_and_warn");
    }

    #[test]
    fn url_variables_resolve_from_overrides_or_skip() {
        let mut remote = http_remote("https://{tenant}.crm.acme.example/mcp");
        remote.variables.insert(
            "tenant".to_owned(),
            InputJson {
                is_required: true,
                ..InputJson::default()
            },
        );
        let unresolved = registry("name: acme\nurl: \"https://r.example\"\n");
        assert!(matches!(
            federation_for_entry(&unresolved, &entry("com.acme/crm", vec![remote.clone()]))
                .unwrap_err(),
            SkipReason::MissingInput(_)
        ));

        let resolved = registry(
            "name: acme\nurl: \"https://r.example\"\nservers:\n  \"com.acme/crm\":\n    variables: { tenant: acme-prod }\n",
        );
        let fed = federation_for_entry(&resolved, &entry("com.acme/crm", vec![remote]))
            .expect("federates");
        assert_eq!(fed.upstream.url, "https://acme-prod.crm.acme.example/mcp");
    }

    #[test]
    fn required_secret_headers_come_from_overrides_or_skip() {
        let mut remote = http_remote("https://crm.acme.example/mcp");
        remote.headers.push(InputJson {
            name: Some("X-API-Key".to_owned()),
            is_required: true,
            is_secret: true,
            ..InputJson::default()
        });
        let missing = registry("name: acme\nurl: \"https://r.example\"\n");
        assert!(matches!(
            federation_for_entry(&missing, &entry("com.acme/crm", vec![remote.clone()]))
                .unwrap_err(),
            SkipReason::MissingInput(_)
        ));

        let supplied = registry(
            "name: acme\nurl: \"https://r.example\"\nservers:\n  \"com.acme/crm\":\n    headers: { X-API-Key: sekrit }\n",
        );
        let fed = federation_for_entry(&supplied, &entry("com.acme/crm", vec![remote]))
            .expect("federates");
        assert_eq!(fed.upstream.headers["X-API-Key"], "sekrit");
    }

    #[test]
    fn registry_url_scheme_of_remote_is_still_gated() {
        // An http:// remote synthesizes allow_insecure_http=false, so
        // federation validation refuses it — the registry cannot relax
        // transport security.
        let reg = registry("name: acme\nurl: \"https://r.example\"\n");
        let plain = entry(
            "com.acme/plain",
            vec![http_remote("http://crm.internal/mcp")],
        );
        assert!(matches!(
            federation_for_entry(&reg, &plain).unwrap_err(),
            SkipReason::Invalid(_)
        ));
    }
}
