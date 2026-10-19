//! The resource as a Personal Agent Protocol (PAP) Company's MCP server
//! (`governance.access.personal_agent`): the PAP view of a verified caller,
//! and the extensions a Personal Agent lists.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue, header};
use dashmap::DashMap;
use mcpg_safe_egress::{EgressPolicy, SafeEgress};
use serde::{Deserialize, Serialize};

use crate::config::personal_agent::{
    AgentExtensionsSource, OPERATIONS_EXTENSION, OPERATIONS_VERSION, OperationsWithoutExtension,
    PersonalAgentConfig,
};
use crate::runtime::RequestIdentity;

/// Most bytes of a client metadata document read.
const MAX_CLIENT_METADATA_BYTES: usize = 16 * 1024;
/// How long a document that could not be read is not asked for again, and
/// the least time any document is used, whatever its `Cache-Control`: a
/// Personal Agent's server is not fetched on every request.
const MIN_DOCUMENT_LIFETIME: Duration = Duration::from_secs(60);
/// Time allowed for one fetch of a client metadata document.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Most documents cached; past it, the expired ones are dropped.
const MAX_CACHED_DOCUMENTS: usize = 10_000;

/// The PAP view of a verified caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalAgentCaller {
    /// The Personal Agent's `client_id`; `None` for a plain MCP client.
    pub client_id: Option<String>,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    /// The account the Session is signed in to.
    pub account: Option<String>,
    pub signed_in: bool,
    /// The extensions the Personal Agent lists, by name, with the major
    /// version it gives; empty when it gives none.
    pub extensions: BTreeMap<String, String>,
}

impl PersonalAgentCaller {
    /// Whether the caller is a Personal Agent rather than a plain MCP
    /// client.
    pub fn is_personal_agent(&self) -> bool {
        self.client_id.is_some()
    }

    /// Whether the Personal Agent lists extension `name` at major
    /// `version`, or with no version.
    pub fn lists(&self, name: &str, version: &str) -> bool {
        self.extensions
            .get(name)
            .is_some_and(|listed| listed.is_empty() || listed == version)
    }
}

/// A client metadata document's extensions, until `until`.
struct CachedExtensions {
    until: Instant,
    extensions: Arc<BTreeMap<String, String>>,
}

/// `governance.access.personal_agent`, resolved.
pub struct PersonalAgentProfile {
    config: PersonalAgentConfig,
    egress: Option<SafeEgress>,
    documents: DashMap<String, CachedExtensions>,
}

impl std::fmt::Debug for PersonalAgentProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonalAgentProfile")
            .field("config", &self.config)
            .field("cached_documents", &self.documents.len())
            .finish_non_exhaustive()
    }
}

impl PersonalAgentProfile {
    pub fn from_config(config: &PersonalAgentConfig) -> anyhow::Result<Self> {
        let egress = match config.agent_extensions.source {
            AgentExtensionsSource::ClientMetadata => {
                let private = config.agent_extensions.allow_private_network;
                let policy = EgressPolicy {
                    max_response_bytes: MAX_CLIENT_METADATA_BYTES,
                    attempt_timeout: FETCH_TIMEOUT,
                    allow_private_backends: private,
                    allow_http: private,
                    user_agent: format!("mcpg/{}", env!("CARGO_PKG_VERSION")),
                    ..EgressPolicy::default()
                };
                Some(SafeEgress::new(policy).map_err(|error| {
                    anyhow::anyhow!("governance.access.personal_agent.agent_extensions: {error}")
                })?)
            }
            AgentExtensionsSource::Attribute | AgentExtensionsSource::None => None,
        };
        Ok(Self {
            config: config.clone(),
            egress,
            documents: DashMap::new(),
        })
    }

    pub fn config(&self) -> &PersonalAgentConfig {
        &self.config
    }

    /// The PAP view of `identity`; `None` for a caller that is not
    /// verified.
    pub async fn caller(&self, identity: &RequestIdentity) -> Option<PersonalAgentCaller> {
        let RequestIdentity::Verified { attributes, .. } = identity else {
            return None;
        };
        let names = &self.config.attributes;
        let get = |name: &str| {
            attributes
                .get(name)
                .filter(|value| !value.is_empty())
                .cloned()
        };
        let client_id = get(&names.client_id);
        let account = get(&names.account);
        let signed_in = match attributes
            .get(&names.signed_in)
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("true") => true,
            Some("false") => false,
            _ => account.is_some(),
        };
        let extensions = match &client_id {
            Some(client_id) => self.extensions(client_id, attributes).await,
            None => BTreeMap::new(),
        };
        Some(PersonalAgentCaller {
            client_id,
            session_id: get(&names.session_id),
            user_id: get(&names.user_id),
            account,
            signed_in,
            extensions,
        })
    }

    /// The first of `require_extensions` that `caller`, a Personal Agent,
    /// does not list, then `operations` at version 1 when
    /// `operations.without_extension` is `refuse_agent`. A plain MCP client
    /// is never refused.
    pub fn missing_extension(&self, caller: &PersonalAgentCaller) -> Option<&str> {
        if !caller.is_personal_agent() {
            return None;
        }
        if let Some(name) = self
            .config
            .require_extensions
            .iter()
            .find(|name| !caller.extensions.contains_key(name.as_str()))
        {
            return Some(name);
        }
        let refuses = self.config.operations.as_ref().is_some_and(|operations| {
            operations.without_extension == OperationsWithoutExtension::RefuseAgent
        });
        (refuses && !caller.lists(OPERATIONS_EXTENSION, OPERATIONS_VERSION))
            .then_some(OPERATIONS_EXTENSION)
    }

    async fn extensions(
        &self,
        client_id: &str,
        attributes: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let source = &self.config.agent_extensions;
        match source.source {
            AgentExtensionsSource::None => BTreeMap::new(),
            AgentExtensionsSource::Attribute => attributes
                .get(&source.attribute)
                .map(|value| extensions_of_attribute(value))
                .unwrap_or_default(),
            AgentExtensionsSource::ClientMetadata => {
                (*self.client_metadata_extensions(client_id).await).clone()
            }
        }
    }

    /// The extensions of the client metadata document at `client_id`, from
    /// the cache while it is fresh.
    async fn client_metadata_extensions(&self, client_id: &str) -> Arc<BTreeMap<String, String>> {
        if let Some(cached) = self.documents.get(client_id)
            && cached.until > Instant::now()
        {
            return Arc::clone(&cached.extensions);
        }
        let ceiling = Duration::from_secs(self.config.agent_extensions.cache_secs);
        let (extensions, lifetime) = match self.fetch(client_id).await {
            Ok((extensions, max_age)) => (
                extensions,
                max_age
                    .map_or(ceiling, |age| age.min(ceiling))
                    .max(MIN_DOCUMENT_LIFETIME),
            ),
            Err(reason) => {
                tracing::warn!(
                    client_id,
                    reason = %reason,
                    "a Personal Agent's client metadata document could not be read; it lists no \
                     extensions until it can"
                );
                (BTreeMap::new(), MIN_DOCUMENT_LIFETIME)
            }
        };
        let extensions = Arc::new(extensions);
        if self.documents.len() >= MAX_CACHED_DOCUMENTS {
            let now = Instant::now();
            self.documents.retain(|_, cached| cached.until > now);
        }
        self.documents.insert(
            client_id.to_owned(),
            CachedExtensions {
                until: Instant::now() + lifetime,
                extensions: Arc::clone(&extensions),
            },
        );
        extensions
    }

    /// Fetch the client metadata document at `client_id`: its extensions,
    /// and how long its `Cache-Control` lets it be used.
    async fn fetch(
        &self,
        client_id: &str,
    ) -> Result<(BTreeMap<String, String>, Option<Duration>), String> {
        let egress = self
            .egress
            .as_ref()
            .ok_or("client metadata documents are not fetched")?;
        let url = egress
            .check_url(client_id)
            .map_err(|refusal| format!("the client_id is not a URL to fetch: {refusal}"))?;
        let allowed = &self.config.agent_extensions.allowed_hosts;
        if !allowed.is_empty()
            && !allowed
                .iter()
                .any(|host| host.eq_ignore_ascii_case(url.host()))
        {
            return Err(format!("{} is not in allowed_hosts", url.host()));
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        let response = egress
            .get(&url, headers)
            .await
            .map_err(|error| format!("the fetch failed: {}", error.category().as_str()))?;
        if !response.status.is_success() {
            return Err(format!("the server answered {}", response.status));
        }
        if response.body_truncated {
            return Err(format!(
                "the document is larger than {MAX_CLIENT_METADATA_BYTES} bytes"
            ));
        }
        let document: serde_json::Value = serde_json::from_slice(&response.body)
            .map_err(|error| format!("the document is not JSON: {error}"))?;
        if let Some(named) = document
            .get("client_id")
            .and_then(serde_json::Value::as_str)
            && named != client_id
        {
            return Err("the document names another client_id".to_owned());
        }
        Ok((
            extensions_of_document(&document),
            cache_lifetime(&response.headers),
        ))
    }
}

/// `extensions` of a client metadata document: name to `{ "version": … }`.
fn extensions_of_document(document: &serde_json::Value) -> BTreeMap<String, String> {
    document
        .get("extensions")
        .and_then(serde_json::Value::as_object)
        .map(|extensions| {
            extensions
                .iter()
                .map(|(name, entry)| (name.clone(), version_of(entry)))
                .collect()
        })
        .unwrap_or_default()
}

/// The major version of an extension entry: its `version` string or
/// number, or empty.
fn version_of(entry: &serde_json::Value) -> String {
    match entry.get("version") {
        Some(serde_json::Value::String(version)) => version.clone(),
        Some(serde_json::Value::Number(version)) => version.to_string(),
        _ => String::new(),
    }
}

/// An identity attribute listing extensions: a JSON object as in a client
/// metadata document, or names separated by spaces.
fn extensions_of_attribute(value: &str) -> BTreeMap<String, String> {
    match serde_json::from_str::<serde_json::Value>(value) {
        Ok(serde_json::Value::Object(extensions)) => extensions
            .iter()
            .map(|(name, entry)| (name.clone(), version_of(entry)))
            .collect(),
        _ => value
            .split_whitespace()
            .map(|name| (name.to_owned(), String::new()))
            .collect(),
    }
}

/// How long `Cache-Control` lets a response be used: `max-age`, or none
/// with `no-store` or `no-cache`.
fn cache_lifetime(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::CACHE_CONTROL)?.to_str().ok()?;
    let mut max_age = None;
    for directive in value.split(',').map(str::trim) {
        let lower = directive.to_ascii_lowercase();
        if lower == "no-store" || lower == "no-cache" {
            return Some(Duration::ZERO);
        }
        if let Some(seconds) = lower.strip_prefix("max-age=") {
            max_age = seconds
                .trim_matches('"')
                .parse::<u64>()
                .ok()
                .map(Duration::from_secs);
        }
    }
    max_age
}

#[cfg(test)]
#[path = "personal_agent_tests.rs"]
mod tests;
