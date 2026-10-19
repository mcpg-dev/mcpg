//! `governance.access.personal_agent`: the resource as a Personal Agent
//! Protocol (PAP) Company's MCP server. The Company's
//! authorization server issues the Session Tokens; `oidc_oauth` or `jwks`
//! verifies them, and its claim mappings fill the identity attributes this
//! block names.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

const AT: &str = "governance.access.personal_agent";
/// Longest extension name accepted.
const MAX_EXTENSION_NAME_CHARS: usize = 128;
/// Bounds of `agent_extensions.cache_secs`.
const MIN_CACHE_SECS: u64 = 60;
const MAX_CACHE_SECS: u64 = 86_400;

/// The Personal Agent Protocol profile of the resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct PersonalAgentConfig {
    /// The identity attributes that carry the Session Token's PAP values,
    /// filled by the verifier's claim mappings (for `oidc_oauth`,
    /// `claim_mappings.attribute_claim_mappings`). A caller with a
    /// `client_id` attribute is a Personal Agent; one without is a plain MCP
    /// client, which signed in with MCP's own flow.
    #[serde(default)]
    pub attributes: PersonalAgentAttributes,
    /// Where the gateway reads the extensions a Personal Agent supports.
    #[serde(default)]
    pub agent_extensions: AgentExtensionsConfig,
    /// Extensions a Personal Agent must list to use this server at all: one
    /// that does not is refused on every request with 403 and
    /// `WWW-Authenticate: <scheme> error="extension_required",
    /// extension="<name>"`. Plain MCP clients are not refused. A plain name
    /// (`operations`) is one the protocol defines; any other starts with a
    /// domain (`example.com/gift-wrap`).
    #[serde(default)]
    pub require_extensions: Vec<String>,
    /// The Company's `poppy.json`, served at `GET /.well-known/poppy.json`.
    #[serde(default)]
    pub discovery: Option<PoppyDiscoveryConfig>,
    /// The operations extension, version 1: the listed tools propose an
    /// operation instead of acting, and the Personal Agent confirms it once
    /// at the operations endpoint.
    #[serde(default)]
    pub operations: Option<OperationsConfig>,
}

/// The path the gateway serves the operations endpoint at: an operation is
/// `{OPERATIONS_PATH}/{operation_id}`, confirmed at `…/confirm` and
/// cancelled at `…/cancel`.
pub const OPERATIONS_PATH: &str = "/poppy/operations";
/// The name a Personal Agent lists the operations extension by.
pub const OPERATIONS_EXTENSION: &str = "operations";
/// The version of the operations extension served.
pub const OPERATIONS_VERSION: &str = "1";

/// `governance.access.personal_agent.operations`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationsConfig {
    /// The operations endpoint's public URL, published in `poppy.json` as
    /// `extensions.operations.endpoint`: an https URL on the origin of a
    /// `resource_metadata` resource, with the path `/poppy/operations`,
    /// where the gateway serves it. It takes DPoP Session Tokens only, so
    /// `governance.access.dpop` (or the embedded server's `dpop`) must be
    /// on.
    pub endpoint: String,
    /// The tools that propose an operation.
    pub tools: Vec<OperationToolConfig>,
    /// What a tool call by a Personal Agent that does not list the
    /// extension does: `perform` runs the tool as without the extension;
    /// `refuse_agent` refuses such a Personal Agent on every request with
    /// `extension_required`, as `require_extensions` does. Plain MCP clients
    /// always run the tool.
    #[serde(default)]
    pub without_extension: OperationsWithoutExtension,
    /// How long a confirm waits for the action to finish before it answers
    /// `in_progress` with `Retry-After`, in seconds (1–30).
    #[serde(default = "default_confirm_wait_secs")]
    pub confirm_wait_secs: u64,
    /// How long a final operation stays readable, in seconds (3600–2592000).
    #[serde(default = "default_retain_final_secs")]
    pub retain_final_secs: u64,
}

fn default_confirm_wait_secs() -> u64 {
    5
}

fn default_retain_final_secs() -> u64 {
    7 * 86_400
}

/// See [`OperationsConfig::without_extension`].
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OperationsWithoutExtension {
    #[default]
    Perform,
    RefuseAgent,
}

/// One tool that proposes an operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationToolConfig {
    /// The MCP tool name.
    pub tool: String,
    /// The terms in plain language, so the User can decide from them alone:
    /// what will happen, to what, and any cost, date or condition. A
    /// template over the call's arguments (`${arguments.order_id}`). The
    /// operation's `terms` are the validated arguments.
    pub summary: String,
    /// The same action proposed again with this key, while its operation is
    /// still `proposed`, revises that operation instead of proposing a new
    /// one: equal terms return it as it is, other terms make the next
    /// revision. A template over the arguments; unset, every call proposes a
    /// new operation.
    #[serde(default)]
    pub action_key: Option<String>,
    /// A page of the Company's website that shows the operation, a template
    /// over the arguments.
    #[serde(default)]
    pub url: Option<String>,
    /// How long a revision can be confirmed, in seconds (60–86400).
    #[serde(default = "default_expires_after_secs")]
    pub expires_after_secs: u64,
    /// Accept only the User's approval of each revision, not a standing
    /// permission.
    #[serde(default)]
    pub user_approval_required: bool,
}

fn default_expires_after_secs() -> u64 {
    900
}

/// Identity attribute names of the PAP values of a Session Token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct PersonalAgentAttributes {
    /// The Personal Agent's `client_id`: the URL of its client metadata
    /// document.
    pub client_id: String,
    /// The Session the token was issued for.
    pub session_id: String,
    /// The User ID the Personal Agent gave the User at this Company. A
    /// plain MCP client's Session has none.
    pub user_id: String,
    /// The account the Session is signed in to, set only while it is.
    pub account: String,
    /// `true` while the Session is signed in. Without this attribute, a
    /// caller is signed in when it has the `account` attribute.
    pub signed_in: String,
}

impl Default for PersonalAgentAttributes {
    fn default() -> Self {
        Self {
            client_id: "client_id".to_owned(),
            session_id: "session_id".to_owned(),
            user_id: "user_id".to_owned(),
            account: "account".to_owned(),
            signed_in: "signed_in".to_owned(),
        }
    }
}

/// Where a Personal Agent's extensions are read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AgentExtensionsConfig {
    /// `client_metadata`: from `extensions` of the client metadata document
    /// at the agent's `client_id` URL, fetched over https without
    /// redirects, private addresses refused, and cached. `attribute`: from
    /// the identity attribute `attribute`, a JSON object of name to
    /// `{ "version": … }` or a space-separated list of names. `none`: no
    /// agent lists any.
    pub source: AgentExtensionsSource,
    /// The identity attribute read with `source: attribute`.
    pub attribute: String,
    /// Hosts a client metadata document may be fetched from; empty allows
    /// any public host.
    pub allowed_hosts: Vec<String>,
    /// Fetch client metadata documents from private addresses too. For a
    /// test network only.
    pub allow_private_network: bool,
    /// How long a fetched document is used, in seconds (60–86400); its
    /// `Cache-Control: max-age` shortens it.
    pub cache_secs: u64,
}

impl Default for AgentExtensionsConfig {
    fn default() -> Self {
        Self {
            source: AgentExtensionsSource::ClientMetadata,
            attribute: "agent_extensions".to_owned(),
            allowed_hosts: Vec::new(),
            allow_private_network: false,
            cache_secs: 3_600,
        }
    }
}

/// See [`AgentExtensionsConfig::source`].
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentExtensionsSource {
    #[default]
    ClientMetadata,
    Attribute,
    None,
}

/// The `poppy.json` document the gateway serves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PoppyDiscoveryConfig {
    /// The document, served as it is with `Cache-Control: max-age=300`. It
    /// needs `protocol_version` `0.x`, `organization.name` and
    /// `organization.domain`, and https URLs for `auth.issuer` and every
    /// `apis[].url`. PAP binds the document to the host that serves it, so
    /// publish it on the Company's own domain only.
    pub document: serde_json::Value,
}

impl PersonalAgentConfig {
    pub fn validate(&self) -> Result<()> {
        let attributes = &self.attributes;
        for (name, value) in [
            ("client_id", &attributes.client_id),
            ("session_id", &attributes.session_id),
            ("user_id", &attributes.user_id),
            ("account", &attributes.account),
            ("signed_in", &attributes.signed_in),
        ] {
            if value.trim().is_empty() {
                bail!("{AT}.attributes.{name} must name an identity attribute");
            }
        }
        let extensions = &self.agent_extensions;
        if !(MIN_CACHE_SECS..=MAX_CACHE_SECS).contains(&extensions.cache_secs) {
            bail!(
                "{AT}.agent_extensions.cache_secs must be between {MIN_CACHE_SECS} and \
                 {MAX_CACHE_SECS}"
            );
        }
        if extensions.source == AgentExtensionsSource::Attribute
            && extensions.attribute.trim().is_empty()
        {
            bail!("{AT}.agent_extensions.attribute must name an identity attribute");
        }
        for (index, name) in self.require_extensions.iter().enumerate() {
            if !valid_extension_name(name) {
                bail!(
                    "{AT}.require_extensions[{index}] `{name}` is not an extension name: a plain \
                     name such as `operations`, or one starting with a domain such as \
                     `example.com/gift-wrap`"
                );
            }
            if self.require_extensions[..index].contains(name) {
                bail!("{AT}.require_extensions lists `{name}` more than once");
            }
        }
        if !self.require_extensions.is_empty() && extensions.source == AgentExtensionsSource::None {
            bail!(
                "{AT}.require_extensions needs agent_extensions.source other than `none`: every \
                 Personal Agent would be refused"
            );
        }
        if let Some(discovery) = &self.discovery {
            validate_poppy_document(&discovery.document)?;
        }
        if let Some(operations) = &self.operations {
            operations.validate()?;
            if self
                .discovery
                .as_ref()
                .and_then(|discovery| discovery.document.get("extensions"))
                .is_some_and(|extensions| !extensions.is_object())
            {
                bail!("{AT}.discovery.document.extensions must be an object");
            }
            if let Some(listed) = self
                .discovery
                .as_ref()
                .and_then(|discovery| discovery.document.pointer("/extensions/operations"))
            {
                let version = listed.get("version").and_then(serde_json::Value::as_str);
                let endpoint = listed.get("endpoint").and_then(serde_json::Value::as_str);
                if version != Some(OPERATIONS_VERSION)
                    || endpoint != Some(operations.endpoint.as_str())
                {
                    bail!(
                        "{AT}.discovery.document.extensions.operations must be {{ \"version\": \
                         \"{OPERATIONS_VERSION}\", \"endpoint\": \"{}\" }}, or left out for the \
                         gateway to add",
                        operations.endpoint
                    );
                }
            }
        }
        Ok(())
    }

    /// The `poppy.json` served: `discovery.document`, with
    /// `extensions.operations` added when operations are on and the
    /// document leaves it out.
    pub fn poppy_document(&self) -> Option<serde_json::Value> {
        let mut document = self.discovery.as_ref()?.document.clone();
        if let Some(operations) = &self.operations
            && let Some(object) = document.as_object_mut()
            && let serde_json::Value::Object(extensions) = object
                .entry("extensions")
                .or_insert_with(|| serde_json::json!({}))
        {
            extensions.entry(OPERATIONS_EXTENSION).or_insert_with(|| {
                serde_json::json!({
                    "version": OPERATIONS_VERSION,
                    "endpoint": operations.endpoint,
                })
            });
        }
        Some(document)
    }
}

impl OperationsConfig {
    pub fn validate(&self) -> Result<()> {
        const OPS: &str = "governance.access.personal_agent.operations";
        let endpoint = url::Url::parse(&self.endpoint)
            .map_err(|e| anyhow!("{OPS}.endpoint `{}` is not a URL: {e}", self.endpoint))?;
        if endpoint.scheme() != "https"
            || endpoint.host().is_none()
            || endpoint.path() != OPERATIONS_PATH
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!(
                "{OPS}.endpoint `{}` must be an https URL whose path is `{OPERATIONS_PATH}`, \
                 where the gateway serves it",
                self.endpoint
            );
        }
        if !(1..=30).contains(&self.confirm_wait_secs) {
            bail!("{OPS}.confirm_wait_secs must be between 1 and 30");
        }
        if !(3_600..=2_592_000).contains(&self.retain_final_secs) {
            bail!("{OPS}.retain_final_secs must be between 3600 and 2592000");
        }
        if self.tools.is_empty() {
            bail!("{OPS}.tools must list at least one tool");
        }
        for (index, tool) in self.tools.iter().enumerate() {
            let at = format!("{OPS}.tools[{index}]");
            if tool.tool.trim().is_empty() {
                bail!("{at}.tool must name a tool");
            }
            if self.tools[..index]
                .iter()
                .any(|other| other.tool == tool.tool)
            {
                bail!("{OPS}.tools lists `{}` more than once", tool.tool);
            }
            if tool.summary.trim().is_empty() {
                bail!("{at}.summary must describe the terms");
            }
            if !(60..=86_400).contains(&tool.expires_after_secs) {
                bail!("{at}.expires_after_secs must be between 60 and 86400");
            }
            for (field, template) in [
                ("summary", Some(&tool.summary)),
                ("action_key", tool.action_key.as_ref()),
                ("url", tool.url.as_ref()),
            ] {
                if let Some(template) = template {
                    validate_template(template, &format!("{at}.{field}"))?;
                }
            }
        }
        Ok(())
    }
}

/// A template over a call's arguments: it compiles, and names no `cred://`
/// reference, since what it renders is shown to the User.
fn validate_template(template: &str, at: &str) -> Result<()> {
    match mcpg_expr::DynamicValue::<String>::parse(template) {
        Ok(mcpg_expr::DynamicValue::Composite { .. }) => {
            bail!("{at} may not name a `cred://` reference")
        }
        Ok(_) => Ok(()),
        Err(error) => bail!("{at} does not compile: {error:#}"),
    }
}

/// An extension name of PAP §3.3: a plain name of letters, digits, `-` and
/// `_`, or a domain, `/` and such a name.
pub fn valid_extension_name(name: &str) -> bool {
    fn plain(part: &str) -> bool {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }
    if name.is_empty() || name.chars().count() > MAX_EXTENSION_NAME_CHARS {
        return false;
    }
    match name.split_once('/') {
        None => plain(name),
        Some((domain, rest)) => {
            domain.contains('.')
                && domain
                    .split('.')
                    .all(|label| plain(label) && !label.contains('_'))
                && plain(rest)
        }
    }
}

fn validate_poppy_document(document: &serde_json::Value) -> Result<()> {
    const DOC: &str = "governance.access.personal_agent.discovery.document";
    let object = document
        .as_object()
        .ok_or_else(|| anyhow!("{DOC} must be a JSON object"))?;
    let version = object
        .get("protocol_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("{DOC}.protocol_version must be a string such as \"0.2\""))?;
    let minor = version.strip_prefix("0.").unwrap_or_default();
    if minor.is_empty() || !minor.chars().all(|c| c.is_ascii_digit()) {
        bail!("{DOC}.protocol_version `{version}` is not a 0.x version this gateway serves");
    }
    let organization = object
        .get("organization")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("{DOC}.organization must be an object"))?;
    for field in ["name", "domain"] {
        if organization
            .get(field)
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            bail!("{DOC}.organization.{field} must be a non-empty string");
        }
    }
    let domain = organization["domain"].as_str().unwrap_or_default();
    if domain.contains('/') || domain.contains(':') || domain.contains(char::is_whitespace) {
        bail!("{DOC}.organization.domain `{domain}` must be a host name, without scheme or path");
    }
    if let Some(auth) = object.get("auth") {
        https_url(auth.get("issuer"), &format!("{DOC}.auth.issuer"))?;
    }
    if let Some(apis) = object.get("apis") {
        let apis = apis
            .as_array()
            .ok_or_else(|| anyhow!("{DOC}.apis must be an array"))?;
        for (index, api) in apis.iter().enumerate() {
            https_url(api.get("url"), &format!("{DOC}.apis[{index}].url"))?;
        }
    }
    Ok(())
}

fn https_url(value: Option<&serde_json::Value>, at: &str) -> Result<()> {
    let raw = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("{at} must be an https URL"))?;
    let url = url::Url::parse(raw).map_err(|e| anyhow!("{at} `{raw}` is not a URL: {e}"))?;
    if url.scheme() != "https" || url.host().is_none() {
        bail!("{at} `{raw}` must be an https URL");
    }
    Ok(())
}

#[cfg(test)]
#[path = "personal_agent_tests.rs"]
mod tests;
