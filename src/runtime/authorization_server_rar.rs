//! Rich Authorization Requests (RFC 9396) at the embedded authorization
//! server: the `authorization_details` a client asks for at the
//! authorization or the token endpoint, or an enterprise IdP puts in an
//! ID-JAG, checked against the types the configuration accepts (RFC 9396
//! §5); the narrowing a token request may apply to what was granted (§6);
//! the lines the consent page shows; and what a verified caller carries.
//!
//! A grant keeps the details the user approved or the IdP granted; each
//! token carries those, or the subset its token request asked for, in its
//! `authorization_details` claim (§9.1) and in the token response (§7). A
//! verified caller carries them as the `authorization_details` and
//! `authorization_details_types` attributes, which a policy reads as
//! `identity.authorization_details`.
//!
//! Nothing here logs or audits a detail's values: a refusal names the
//! entry and the rule it breaks, an audit record the types and a digest
//! keyed from the first signing key, and the audit trail carries a
//! caller's `authorization_details` attribute as that digest too
//! (`mcpg_plugin_host::audit_events::DIGESTED_ACTOR_ATTRIBUTES`). The key
//! stops an audit reader from recovering low-entropy details by digesting
//! candidates.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{AuthorizationServer, OAuthError};
use crate::config::{AuthorizationDetailLocations, AuthorizationDetailsConfig};

/// Identity attribute of a caller whose token is limited to authorization
/// details: the details, as canonical JSON ([`AuthorizationDetails::to_json`]).
pub const AUTHORIZATION_DETAILS_ATTRIBUTE: &str = "authorization_details";
/// Identity attribute naming the distinct types of those details,
/// separated by spaces.
pub const AUTHORIZATION_DETAILS_TYPES_ATTRIBUTE: &str = "authorization_details_types";
/// Largest `authorization_details` accepted, as JSON, in bytes.
pub const MAX_DETAILS_BYTES: usize = 8 * 1024;
/// Most values one common array member may hold.
const MAX_FIELD_VALUES: usize = 64;
/// The members RFC 9396 §2.2 defines as arrays of strings.
const ARRAY_FIELDS: [&str; 4] = ["locations", "actions", "datatypes", "privileges"];
/// Every member RFC 9396 §2 defines.
const COMMON_FIELDS: [&str; 6] = [
    "type",
    "locations",
    "actions",
    "datatypes",
    "identifier",
    "privileges",
];
/// RFC 5869 `info` of the key audit records digest details under.
const AUDIT_DIGEST_KEY_INFO: &[u8] = b"mcpg:as-audit-digest:v1";

/// The key audit records digest authorization details under: RFC 5869 with
/// the issuer as salt over a signing key's material, so every replica
/// carrying the key writes the same digests.
pub(super) fn audit_digest_key(issuer: &str, material: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(issuer.as_bytes()), material)
        .expand(AUDIT_DIGEST_KEY_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("the audit digest key cannot be derived"))?;
    Ok(key)
}

/// A valid `authorization_details` array: objects of the types the server
/// accepts, in the order given. `Debug` shows the types only.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorizationDetails(Vec<Map<String, Value>>);

impl std::fmt::Debug for AuthorizationDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AuthorizationDetails")
            .field(&self.types())
            .finish()
    }
}

impl AuthorizationDetails {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The objects, in order.
    pub fn entries(&self) -> &[Map<String, Value>] {
        &self.0
    }

    /// The distinct types, in the order they first appear.
    pub fn types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = Vec::new();
        for entry in &self.0 {
            if let Some(name) = entry.get("type").and_then(Value::as_str)
                && !types.contains(&name)
            {
                types.push(name);
            }
        }
        types
    }

    /// The details as canonical JSON: compact, the members of every object
    /// sorted.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&canonical(&Value::Array(
            self.0.iter().cloned().map(Value::Object).collect(),
        )))
        .unwrap_or_default()
    }

    /// The keyed digest of [`Self::to_json`] under `key`, which correlates
    /// audit records without their content: it is what an audit record
    /// carries for the caller's `authorization_details` attribute, digested
    /// under the same key.
    pub fn audit_digest(&self, key: &[u8; 32]) -> String {
        mcpg_plugin_host::audit_events::attribute_digest(key, &self.to_json())
    }

    /// Whether every object of `requested` is covered by an object of these
    /// details (RFC 9396 §6): of the same type, holding a subset of each of
    /// its arrays (`locations`, `actions`, `datatypes`, `privileges`) where
    /// both carry it, neither carrying one the other lacks, and equal in
    /// every other member.
    pub fn covers(&self, requested: &AuthorizationDetails) -> bool {
        requested
            .0
            .iter()
            .all(|wanted| self.0.iter().any(|granted| covers_one(granted, wanted)))
    }

    /// The details a caller's `authorization_details` attribute holds.
    /// `None` for anything but a JSON array of objects.
    pub fn from_attribute(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }
}

/// Whether `granted` covers `wanted`.
fn covers_one(granted: &Map<String, Value>, wanted: &Map<String, Value>) -> bool {
    granted.keys().chain(wanted.keys()).all(|member| {
        match (granted.get(member), wanted.get(member)) {
            (Some(Value::Array(granted)), Some(Value::Array(wanted)))
                if ARRAY_FIELDS.contains(&member.as_str()) =>
            {
                wanted.iter().all(|value| granted.contains(value))
            }
            (granted, wanted) => granted == wanted,
        }
    })
}

/// `value` with the members of every object sorted.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(members) => {
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(name, value)| (name.clone(), canonical(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Where a list of details was asked for, as a bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DetailsSource {
    /// The authorization endpoint's parameter.
    Authorize,
    /// The token request that redeems an authorization code.
    Token,
    /// An ID-JAG and the token request that redeems it.
    IdJag,
    /// A refresh.
    Refresh,
}

impl DetailsSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Token => "token",
            Self::IdJag => "id_jag",
            Self::Refresh => "refresh",
        }
    }
}

/// What became of a list of details, as a bounded metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailsOutcome {
    Granted,
    Narrowed,
    Refused,
}

impl DetailsOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Narrowed => "narrowed",
            Self::Refused => "refused",
        }
    }
}

fn count(source: DetailsSource, outcome: DetailsOutcome) {
    metrics::counter!(
        "mcpg_as_authorization_details_total",
        "source" => source.as_str(),
        "outcome" => outcome.as_str(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/// The rules of one accepted type.
struct TypeRule {
    name: String,
    description: Option<String>,
    schema: Option<jsonschema::Validator>,
    actions: Option<Vec<String>>,
    datatypes: Option<Vec<String>>,
    privileges: Option<Vec<String>>,
    locations: AuthorizationDetailLocations,
}

impl TypeRule {
    /// The allowlist of the array member `field`, if the type has one.
    fn allowlist(&self, field: &str) -> Option<&[String]> {
        match field {
            "actions" => self.actions.as_deref(),
            "datatypes" => self.datatypes.as_deref(),
            "privileges" => self.privileges.as_deref(),
            _ => None,
        }
    }
}

/// The authorization details settings of one server, resolved from its
/// configuration.
pub(super) struct RarSettings {
    types: Vec<TypeRule>,
    max_entries: usize,
    /// The resource identifiers a `locations` value may name, without a
    /// trailing `/`.
    resources: Vec<String>,
}

impl std::fmt::Debug for RarSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RarSettings")
            .field("types", &self.type_names())
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

impl RarSettings {
    /// `config`, for a server that serves `resources`.
    pub(super) fn from_config(
        config: &AuthorizationDetailsConfig,
        resources: &[String],
    ) -> Result<Self> {
        let at = "governance.access.authorization_server.authorization_details";
        let types = config
            .types
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let schema = rule
                    .schema
                    .as_ref()
                    .map(|schema| {
                        crate::config::schema_safety::compile_checked(
                            schema,
                            &format!("{at}.types[{index}].schema"),
                        )
                    })
                    .transpose()?;
                Ok(TypeRule {
                    name: rule.type_name.clone(),
                    description: rule.description.clone(),
                    schema,
                    actions: rule.actions.clone(),
                    datatypes: rule.datatypes.clone(),
                    privileges: rule.privileges.clone(),
                    locations: rule.locations,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            types,
            max_entries: usize::try_from(config.max_entries).unwrap_or(usize::MAX),
            resources: resources
                .iter()
                .map(|resource| resource.trim_end_matches('/').to_owned())
                .collect(),
        })
    }

    /// Whether RFC 9396 is on.
    pub(super) fn enabled(&self) -> bool {
        !self.types.is_empty()
    }

    /// The accepted types, as configured.
    pub(super) fn type_names(&self) -> Vec<&str> {
        self.types.iter().map(|rule| rule.name.as_str()).collect()
    }

    fn rule(&self, name: &str) -> Option<&TypeRule> {
        self.types.iter().find(|rule| rule.name == name)
    }

    /// The details of a request parameter: at most [`MAX_DETAILS_BYTES`],
    /// then JSON, then [`Self::parse`]. Else why not, naming no value.
    pub(super) fn parse_parameter(&self, raw: &str) -> Result<AuthorizationDetails, String> {
        if raw.len() > MAX_DETAILS_BYTES {
            return Err(format!(
                "authorization_details exceeds {MAX_DETAILS_BYTES} bytes"
            ));
        }
        let value: Value = serde_json::from_str(raw)
            .map_err(|_| "authorization_details is not valid JSON".to_owned())?;
        self.parse(&value)
    }

    /// `value` as details every rule of RFC 9396 §5 and of the configured
    /// types admits: a JSON array of 1 to `max_entries` objects, at most
    /// [`MAX_DETAILS_BYTES`] of JSON, each of an accepted `type`, its
    /// common members well formed and within the type's allowlists, and
    /// no other member unless the type's schema admits it. Else why not,
    /// naming the entry and the rule but no value.
    pub(super) fn parse(&self, value: &Value) -> Result<AuthorizationDetails, String> {
        let Some(entries) = value.as_array() else {
            return Err("authorization_details must be a JSON array of objects".to_owned());
        };
        if entries.is_empty() || entries.len() > self.max_entries {
            return Err(format!(
                "authorization_details must hold 1 to {} objects",
                self.max_entries
            ));
        }
        if serde_json::to_vec(value)
            .ok()
            .is_none_or(|json| json.len() > MAX_DETAILS_BYTES)
        {
            return Err(format!(
                "authorization_details exceeds {MAX_DETAILS_BYTES} bytes"
            ));
        }
        entries
            .iter()
            .enumerate()
            .map(|(index, entry)| self.parse_entry(index, entry))
            .collect::<Result<Vec<_>, _>>()
            .map(AuthorizationDetails)
    }

    fn parse_entry(&self, index: usize, entry: &Value) -> Result<Map<String, Value>, String> {
        let at = format!("authorization_details[{index}]");
        let Some(members) = entry.as_object() else {
            return Err(format!("{at} is not a JSON object"));
        };
        let Some(name) = members.get("type").and_then(Value::as_str) else {
            return Err(format!("{at}.type is missing or not a string"));
        };
        let Some(rule) = self.rule(name) else {
            return Err(format!("{at}.type is not a type this server accepts"));
        };
        for field in ARRAY_FIELDS {
            let Some(values) = members.get(field) else {
                continue;
            };
            let Some(values) = values
                .as_array()
                .filter(|values| values.len() <= MAX_FIELD_VALUES)
                .and_then(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().filter(|value| !value.is_empty()))
                        .collect::<Option<Vec<&str>>>()
                })
            else {
                return Err(format!(
                    "{at}.{field} must be an array of at most {MAX_FIELD_VALUES} non-empty strings"
                ));
            };
            if let Some(allowed) = rule.allowlist(field)
                && !values
                    .iter()
                    .all(|value| allowed.iter().any(|ok| ok == value))
            {
                return Err(format!(
                    "{at}.{field} holds a value its type does not allow"
                ));
            }
            if field == "locations"
                && rule.locations == AuthorizationDetailLocations::Resource
                && !values.iter().all(|location| {
                    let location = location.trim_end_matches('/');
                    self.resources.iter().any(|ours| ours == location)
                })
            {
                return Err(format!(
                    "{at}.locations names a location that is not a resource of this server"
                ));
            }
        }
        if members
            .get("identifier")
            .is_some_and(|identifier| !identifier.is_string())
        {
            return Err(format!("{at}.identifier must be a string"));
        }
        match rule.schema {
            Some(ref schema) => {
                if !schema.is_valid(entry) {
                    return Err(format!("{at} does not satisfy the schema of its type"));
                }
            }
            None => {
                if members
                    .keys()
                    .any(|member| !COMMON_FIELDS.contains(&member.as_str()))
                {
                    return Err(format!(
                        "{at} carries a member its type does not define (RFC 9396 section 2)"
                    ));
                }
            }
        }
        Ok(members.clone())
    }

    /// The consent page's lines for `details`, each member whole: the user
    /// approves every value a token will carry, so none is cut.
    pub(super) fn consent_lines(&self, details: &AuthorizationDetails) -> Vec<DetailLine> {
        details
            .entries()
            .iter()
            .map(|entry| {
                let type_name = entry
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let strings = |field: &str| -> Vec<String> {
                    entry
                        .get(field)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                };
                let others: Map<String, Value> = entry
                    .iter()
                    .filter(|(member, _)| !COMMON_FIELDS.contains(&member.as_str()))
                    .map(|(member, value)| (member.clone(), value.clone()))
                    .collect();
                let other = (!others.is_empty()).then(|| {
                    let others = Value::Object(others);
                    serde_json::to_string_pretty(&others).unwrap_or_else(|_| others.to_string())
                });
                DetailLine {
                    label: self
                        .rule(&type_name)
                        .and_then(|rule| rule.description.clone())
                        .unwrap_or_else(|| type_name.clone()),
                    actions: strings("actions"),
                    locations: strings("locations"),
                    datatypes: strings("datatypes"),
                    privileges: strings("privileges"),
                    identifier: entry
                        .get("identifier")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    other,
                    type_name,
                }
            })
            .collect()
    }
}

/// One authorization details object on the consent page, as the user
/// reads it. `Debug` shows the type only.
#[derive(Clone, PartialEq, Eq)]
pub struct DetailLine {
    /// The type's `description`, else the type.
    pub label: String,
    pub type_name: String,
    pub actions: Vec<String>,
    pub locations: Vec<String>,
    pub datatypes: Vec<String>,
    pub privileges: Vec<String>,
    pub identifier: Option<String>,
    /// The other members as indented JSON, whole.
    pub other: Option<String>,
}

impl std::fmt::Debug for DetailLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetailLine")
            .field("type_name", &self.type_name)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

impl AuthorizationServer {
    /// Whether RFC 9396 is on.
    pub fn authorization_details_enabled(&self) -> bool {
        self.rar.enabled()
    }

    /// The types published as `authorization_details_types_supported`.
    pub fn authorization_details_types(&self) -> Vec<&str> {
        self.rar.type_names()
    }

    /// The key audit records digest the `authorization_details` attribute
    /// under, from the first signing key: the plugin registry is given it,
    /// so a token's issuance record and its callers' records correlate.
    pub fn audit_digest_key(&self) -> Zeroizing<[u8; 32]> {
        self.signing_keys[0].audit_key.clone()
    }

    /// The keyed digest an issuance record carries for `details`; `None`
    /// without details.
    pub(super) fn details_digest(&self, details: &AuthorizationDetails) -> Option<String> {
        (!details.is_empty()).then(|| details.audit_digest(&self.signing_keys[0].audit_key))
    }

    /// The details of an ID-JAG's `authorization_details` claim, which
    /// must all be valid (ID-JAG §4.4.1): a refusal is `invalid_grant`,
    /// since the assertion is the grant. While RFC 9396 is off, any
    /// details are refused rather than dropped, which would mint a token
    /// wider than the IdP granted.
    pub(super) fn assertion_details(
        &self,
        claim: Option<&Value>,
    ) -> Result<AuthorizationDetails, OAuthError> {
        let Some(claim) = claim else {
            return Ok(AuthorizationDetails::default());
        };
        if !self.rar.enabled() {
            return Err(OAuthError::invalid_grant(
                "the assertion carries authorization_details, which this authorization server \
                 does not support (RFC 9396)",
            ));
        }
        self.rar.parse(claim).map_err(|problem| {
            count(DetailsSource::IdJag, DetailsOutcome::Refused);
            OAuthError::invalid_grant(format!("the assertion's {problem}"))
        })
    }

    /// The details of an authorization request's `authorization_details`
    /// parameter, while RFC 9396 is on; none otherwise, where the parameter
    /// is unknown and ignored (RFC 6749 §3.1). Else why they are refused.
    pub(super) fn authorize_details(
        &self,
        raw: Option<&str>,
    ) -> Result<AuthorizationDetails, String> {
        let Some(raw) = raw.filter(|_| self.rar.enabled()) else {
            return Ok(AuthorizationDetails::default());
        };
        let parsed = self.rar.parse_parameter(raw);
        count(
            DetailsSource::Authorize,
            if parsed.is_ok() {
                DetailsOutcome::Granted
            } else {
                DetailsOutcome::Refused
            },
        );
        parsed
    }

    /// The details a token carries: `granted`, or the narrowing of it that
    /// a token request's `authorization_details` parameter (`requested`)
    /// asks for, each of whose objects `granted` must cover (RFC 9396 §6).
    /// A parameter that is not valid, asks for more than was granted, or
    /// narrows a grant without details is `invalid_authorization_details`.
    /// While RFC 9396 is off, the parameter is ignored.
    pub(super) fn requested_details(
        &self,
        granted: &AuthorizationDetails,
        requested: Option<&str>,
        source: DetailsSource,
    ) -> Result<AuthorizationDetails, OAuthError> {
        let requested = requested
            .filter(|raw| !raw.is_empty())
            .filter(|_| self.rar.enabled());
        let Some(raw) = requested else {
            if !granted.is_empty() {
                count(source, DetailsOutcome::Granted);
            }
            return Ok(granted.clone());
        };
        let refused = |description: String| {
            count(source, DetailsOutcome::Refused);
            OAuthError::invalid_authorization_details(description)
        };
        if granted.is_empty() {
            return Err(refused(
                "the grant carries no authorization_details for the request to narrow".to_owned(),
            ));
        }
        let wanted = self.rar.parse_parameter(raw).map_err(refused)?;
        if !granted.covers(&wanted) {
            return Err(refused(
                "the requested authorization_details exceed what was granted".to_owned(),
            ));
        }
        count(source, DetailsOutcome::Narrowed);
        Ok(wanted)
    }

    /// The consent page's lines for `details`.
    pub(super) fn detail_lines(&self, details: &AuthorizationDetails) -> Vec<DetailLine> {
        self.rar.consent_lines(details)
    }
}
