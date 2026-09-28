//! Client authentication at the token endpoint (RFC 6749 §2.3): shared
//! secrets, `private_key_jwt` assertions (RFC 7523 §2.2) and public
//! clients, for registered clients, for clients described by a Client ID
//! Metadata Document (`draft-ietf-oauth-client-id-metadata-document`) and
//! for dynamically registered ones ([`super::dcr`]), which are public.
//! Also the client of an authorization request: a registered client whose
//! `grant_types` allow `authorization_code`, a dynamic registration, or a
//! document that names the client and its redirect URIs, read only while
//! fresh.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine as _;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use super::redirect::{
    AuthorizeClient, AuthorizeClientError, RedirectError, RedirectRegistration,
    client_display_name, consent_rule,
};
use super::state::{ClientKind, DcrClientRecord};
use super::upstream::{check_answering_address, pinned_client, read_capped};
use super::{
    AuthorizationServer, ECHO_LIMIT, FetchFailure, KeyCache, KeyError, KeyOwner,
    MAX_IDP_RESPONSE_BYTES, OAuthError, StringOrVec, TOKEN_PATH, TokenRequestForm, ct_eq,
    enforce_discovery_url_safety, now_unix, percent_decode, select_key, status_failure,
    unverified_claim_str,
};
use crate::config::access::parse_public_jwks;
pub use crate::config::interactive_login::DCR_CLIENT_ID_PREFIX;
use crate::config::interactive_login::DynamicClientRegistrationConfig;
use crate::config::{
    AuthorizationServerClientConfig, ClientAuthMethod, ClientConsent, ClientGrantType,
    ClientIdMetadataDocumentsConfig,
};

/// RFC 7523 §2.2 `client_assertion_type` of a `private_key_jwt` request.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Algorithms a client assertion may be signed with, by their JWA names.
pub(super) const CLIENT_ASSERTION_ALGS: [(Algorithm, &str); 9] = [
    (Algorithm::RS256, "RS256"),
    (Algorithm::RS384, "RS384"),
    (Algorithm::RS512, "RS512"),
    (Algorithm::PS256, "PS256"),
    (Algorithm::PS384, "PS384"),
    (Algorithm::PS512, "PS512"),
    (Algorithm::ES256, "ES256"),
    (Algorithm::ES384, "ES384"),
    (Algorithm::EdDSA, "EdDSA"),
];
/// Furthest ahead a client assertion's `exp` may lie; it also bounds how
/// long a used `jti` is remembered.
const MAX_CLIENT_ASSERTION_LIFETIME_SECS: u64 = 300;
/// Key namespace of used client assertions in the replay ledger.
const CLIENT_ASSERTION_KEY_PREFIX: &str = "ema_client_jti/";
/// Largest client metadata document read, the size the draft recommends
/// as a ceiling.
const MAX_CLIENT_METADATA_BYTES: usize = 5 * 1024;
/// Longest client identifier URL resolved.
const MAX_CLIENT_ID_URL_BYTES: usize = 2048;
/// How long a document without `Cache-Control: max-age` is reused.
const CLIENT_METADATA_DEFAULT_TTL: Duration = Duration::from_secs(300);
/// Bounds on a document's reuse: the floor spares the document host and
/// this gateway's egress, the ceiling bounds how long a withdrawn client
/// keeps working.
const CLIENT_METADATA_MIN_TTL: Duration = Duration::from_secs(60);
const CLIENT_METADATA_MAX_TTL: Duration = Duration::from_secs(86_400);
/// Minimum spacing between fetches of one document.
const CLIENT_METADATA_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// How long the last document that validated keeps serving while its host
/// cannot be reached.
const CLIENT_METADATA_MAX_STALENESS: Duration = Duration::from_secs(3600);
/// Most metadata documents held at once; the least recently used goes.
const MAX_CACHED_CLIENT_METADATA: usize = 1024;
/// Timeout of one metadata document or client key fetch: a first request
/// may also fetch the IdP's keys, and clients such as Claude give the
/// whole token request 10 seconds.
const CLIENT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How a client proves its identity at the token endpoint.
pub(super) enum ClientAuth {
    /// `client_secret_basic` and/or `client_secret_post`.
    Secret {
        secret: String,
        basic: bool,
        post: bool,
    },
    PrivateKeyJwt {
        keys: ClientKeys,
        accept_token_endpoint_audience: bool,
    },
    /// `none`: a public client.
    Public,
}

/// The public keys a `private_key_jwt` client signs its assertions with.
pub(super) enum ClientKeys {
    Inline(JwkSet),
    Remote {
        uri: String,
        /// Hosts the key URL must stay on; empty = any public host.
        allowed_hosts: Vec<String>,
        allow_private: bool,
        cache: KeyCache,
    },
}

/// A client the token endpoint can authenticate.
pub(super) struct Client {
    pub(super) client_id: String,
    auth: ClientAuth,
    interactive: InteractiveProfile,
    /// Whether it may redeem ID-JAGs: a registered client whose
    /// `grant_types` hold jwt-bearer, and any metadata document's client;
    /// never a dynamically registered one.
    redeems_id_jags: bool,
    /// RFC 9449 §5.2: every token request must carry a DPoP proof. Read
    /// only while DPoP is on.
    dpop_bound_access_tokens: bool,
}

/// What a client may do at the authorization endpoint.
struct InteractiveProfile {
    kind: ClientKind,
    name: Option<String>,
    application_type: Option<String>,
    redirects: RedirectRegistration,
    refresh_allowed: bool,
    /// Read for a registered client only.
    consent: ClientConsent,
    /// Why the client cannot sign users in, if it cannot.
    refusal: Option<AuthorizeClientError>,
}

impl InteractiveProfile {
    /// A registered client's: its `grant_types` decide.
    fn from_config(config: &AuthorizationServerClientConfig, at: &str) -> Result<Self> {
        let redirects = RedirectRegistration::from_uris(&config.redirect_uris)
            .map_err(|problem| anyhow::anyhow!("{at}.redirect_uris entry {problem}"))?;
        let refusal = (!config.allows_grant(ClientGrantType::AuthorizationCode)).then(|| {
            AuthorizeClientError::Unauthorized(
                "its registration's grant_types lack authorization_code".to_owned(),
            )
        });
        Ok(Self {
            kind: ClientKind::Static,
            name: config.client_name.clone(),
            application_type: None,
            redirects,
            refresh_allowed: config.allows_grant(ClientGrantType::RefreshToken),
            consent: config.consent,
            refusal,
        })
    }

    /// A metadata document's at `url`. It must name the client
    /// (`client_name`) and list `redirect_uris`; `response_types` is absent
    /// or `["code"]`; `grant_types`, `[authorization_code]` when absent
    /// (RFC 7591 §2), must hold `authorization_code`, and a refresh token
    /// is issued only when it holds `refresh_token`.
    fn from_document(
        url: &str,
        document: &ClientMetadataDocument,
        config: &ClientIdMetadataDocumentsConfig,
    ) -> Self {
        let redirect_uris = string_array(document.redirect_uris.as_ref(), "redirect_uris");
        let grant_types = string_array(document.grant_types.as_ref(), "grant_types");
        let response_types = string_array(document.response_types.as_ref(), "response_types");
        let redirects = match redirect_uris {
            Ok(Some(ref entries)) => RedirectRegistration::from_document(entries, url, config),
            _ => RedirectRegistration::default(),
        };
        let name = document
            .client_name
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .and_then(client_display_name);
        let refusal = match (&redirect_uris, &response_types, &grant_types) {
            (Err(problem), _, _) | (_, Err(problem), _) | (_, _, Err(problem)) => {
                Some(AuthorizeClientError::InvalidDocument(problem.clone()))
            }
            (Ok(None), _, _) => Some(AuthorizeClientError::InvalidDocument(
                "it lists no redirect_uris".to_owned(),
            )),
            (Ok(Some(entries)), _, _) if entries.is_empty() => Some(
                AuthorizeClientError::InvalidDocument("it lists no redirect_uris".to_owned()),
            ),
            _ if name.is_none() => Some(AuthorizeClientError::InvalidDocument(
                "it carries no client_name, which the consent page shows".to_owned(),
            )),
            (_, Ok(Some(types)), _) if types.is_empty() || types.iter().any(|t| *t != "code") => {
                Some(AuthorizeClientError::InvalidDocument(
                    "its response_types must be [\"code\"] when present".to_owned(),
                ))
            }
            (_, _, Ok(Some(grants))) if !grants.contains(&"authorization_code") => {
                Some(AuthorizeClientError::Unauthorized(
                    "its metadata document's grant_types lack authorization_code".to_owned(),
                ))
            }
            _ => None,
        };
        let refresh_allowed =
            matches!(grant_types, Ok(Some(ref grants)) if grants.contains(&"refresh_token"));
        let application_type = document
            .application_type
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .filter(|kind| matches!(*kind, "web" | "native"))
            .map(str::to_owned);
        Self {
            kind: ClientKind::Cimd,
            name,
            application_type,
            redirects,
            refresh_allowed,
            consent: ClientConsent::Always,
            refusal,
        }
    }

    /// A dynamic registration's: its `redirect_uris` as the policy admits
    /// them now, and its `grant_types`. Consent is always asked.
    fn from_registration(
        record: &DcrClientRecord,
        config: &DynamicClientRegistrationConfig,
    ) -> Self {
        let registered = |grant: ClientGrantType| {
            record
                .grant_types
                .iter()
                .any(|listed| listed == grant.as_str())
        };
        let refusal = (!registered(ClientGrantType::AuthorizationCode)).then(|| {
            AuthorizeClientError::Unauthorized(
                "its registration's grant_types lack authorization_code".to_owned(),
            )
        });
        Self {
            kind: ClientKind::Dcr,
            name: record.client_name.as_deref().and_then(client_display_name),
            application_type: record.application_type.clone(),
            redirects: RedirectRegistration::from_registration(&record.redirect_uris, |host| {
                config.admits_redirect_host(host)
            }),
            refresh_allowed: registered(ClientGrantType::RefreshToken),
            consent: ClientConsent::Always,
            refusal,
        }
    }

    /// The client `client_id` with this profile, for an authorization
    /// request that names `requested` as its redirect URI.
    fn authorize(
        &self,
        client_id: &str,
        requested: Option<&str>,
    ) -> Result<AuthorizeClient, AuthorizeClientError> {
        if let Some(ref refusal) = self.refusal {
            return Err(refusal.clone());
        }
        let redirect = self
            .redirects
            .resolve(self.kind, requested)
            .map_err(AuthorizeClientError::Redirect)?;
        Ok(AuthorizeClient {
            client_id: client_id.to_owned(),
            kind: self.kind,
            name: self.name.clone(),
            application_type: self.application_type.clone(),
            consent: consent_rule(self.kind, self.consent, &self.redirects, redirect.kind),
            refresh_allowed: self.refresh_allowed,
            redirect,
        })
    }
}

/// A document member that must be an array of strings: `Ok(None)` when
/// absent, `Err` when of another shape.
fn string_array<'a>(
    member: Option<&'a serde_json::Value>,
    name: &str,
) -> Result<Option<Vec<&'a str>>, String> {
    match member {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| format!("its {name} holds an entry that is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("its {name} is not an array of strings")),
    }
}

impl Client {
    /// A registered client (`clients[]`), which config validation has
    /// already checked.
    pub(super) fn from_config(config: &AuthorizationServerClientConfig) -> Result<Self> {
        let at = format!("clients[`{}`]", config.client_id);
        let interactive = InteractiveProfile::from_config(config, &at)?;
        let methods = config.effective_auth_methods().ok_or_else(|| {
            anyhow::anyhow!("{at}: set token_endpoint_auth_method to pick one method")
        })?;
        let auth = match methods[0] {
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
                ClientAuth::Secret {
                    secret: config
                        .client_secret
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("{at}: needs a client_secret"))?,
                    basic: methods.contains(&ClientAuthMethod::ClientSecretBasic),
                    post: methods.contains(&ClientAuthMethod::ClientSecretPost),
                }
            }
            ClientAuthMethod::PrivateKeyJwt => {
                let keys = match (&config.jwks, &config.jwks_uri) {
                    (Some(jwks), None) => ClientKeys::Inline(
                        parse_public_jwks(jwks).map_err(|e| anyhow::anyhow!("{at}.jwks {e}"))?,
                    ),
                    (None, Some(uri)) => ClientKeys::Remote {
                        uri: uri.clone(),
                        allowed_hosts: Vec::new(),
                        allow_private: config.allow_private_network,
                        cache: KeyCache::default(),
                    },
                    _ => anyhow::bail!(
                        "{at}: private_key_jwt needs exactly one of jwks and jwks_uri"
                    ),
                };
                ClientAuth::PrivateKeyJwt {
                    keys,
                    accept_token_endpoint_audience: config.accept_token_endpoint_audience,
                }
            }
            ClientAuthMethod::None => ClientAuth::Public,
        };
        Ok(Self {
            client_id: config.client_id.clone(),
            auth,
            interactive,
            redeems_id_jags: config.allows_grant(ClientGrantType::JwtBearer),
            dpop_bound_access_tokens: config.dpop_bound_access_tokens,
        })
    }

    /// A dynamically registered client: public, and never an ID-JAG
    /// redeemer.
    pub(super) fn from_registration(
        record: &DcrClientRecord,
        config: &DynamicClientRegistrationConfig,
    ) -> Self {
        Self {
            client_id: record.client_id.clone(),
            auth: ClientAuth::Public,
            interactive: InteractiveProfile::from_registration(record, config),
            redeems_id_jags: false,
            dpop_bound_access_tokens: record.dpop_bound_access_tokens,
        }
    }

    /// Whether this client may redeem ID-JAGs.
    pub(super) fn redeems_id_jags(&self) -> bool {
        self.redeems_id_jags
    }

    /// Whether this client authenticates with nothing but its `client_id`
    /// (`none`): a public registered or metadata document client, and every
    /// dynamically registered one.
    pub(super) fn is_public(&self) -> bool {
        matches!(self.auth, ClientAuth::Public)
    }

    /// Whether this client declared that every token it receives is bound
    /// to a DPoP key (RFC 9449 §5.2).
    pub(super) fn dpop_bound_access_tokens(&self) -> bool {
        self.dpop_bound_access_tokens
    }

    /// This client, for an authorization request that names `requested`
    /// as its redirect URI.
    pub(super) fn authorize(
        &self,
        requested: Option<&str>,
    ) -> Result<AuthorizeClient, AuthorizeClientError> {
        self.interactive.authorize(&self.client_id, requested)
    }

    /// Why this client may not redeem an authorization code, if it may
    /// not: its registration's or metadata document's `grant_types` lack
    /// `authorization_code`, or its document cannot sign users in.
    pub(super) fn code_grant_refusal(&self) -> Option<&AuthorizeClientError> {
        self.interactive.refusal.as_ref()
    }

    /// Whether a grant of this client may come with a refresh token: its
    /// `grant_types` hold `refresh_token`.
    pub(super) fn refresh_allowed(&self) -> bool {
        self.interactive.refresh_allowed
    }

    pub(super) fn kind(&self) -> ClientKind {
        self.interactive.kind
    }

    /// The token endpoint authentication methods this client uses.
    pub(super) fn methods(&self) -> Vec<ClientAuthMethod> {
        match self.auth {
            ClientAuth::Secret { basic, post, .. } => [
                basic.then_some(ClientAuthMethod::ClientSecretBasic),
                post.then_some(ClientAuthMethod::ClientSecretPost),
            ]
            .into_iter()
            .flatten()
            .collect(),
            ClientAuth::PrivateKeyJwt { .. } => vec![ClientAuthMethod::PrivateKeyJwt],
            ClientAuth::Public => vec![ClientAuthMethod::None],
        }
    }
}

/// What a token request presents to authenticate its client.
enum Credential<'a> {
    /// `client_secret_basic`: the secret from the `Authorization` header.
    Basic(String),
    /// `client_secret_post`: the `client_secret` form field.
    Post(String),
    /// `private_key_jwt`: the `client_assertion` form field.
    Assertion(&'a str),
    /// No credential: a public client.
    Nothing,
}

impl AuthorizationServer {
    /// Authenticate the client of a token request with exactly one method,
    /// the one the client uses.
    pub(super) async fn authenticate(
        &self,
        form: &TokenRequestForm,
        authorization: Option<&str>,
    ) -> Result<Arc<Client>, OAuthError> {
        let basic = authorization.and_then(|v| {
            v.strip_prefix("Basic ")
                .or_else(|| v.strip_prefix("basic "))
        });
        let form_secret = form.client_secret.as_deref().filter(|s| !s.is_empty());
        let assertion_sent =
            form.client_assertion.is_some() || form.client_assertion_type.is_some();
        // RFC 6749 §2.3: a client MUST NOT use more than one method.
        if usize::from(basic.is_some())
            + usize::from(form_secret.is_some())
            + usize::from(assertion_sent)
            > 1
        {
            return Err(OAuthError::new(
                "invalid_request",
                "the request authenticates the client more than one way; use exactly one of HTTP \
                 Basic, client_secret and client_assertion",
            ));
        }
        let form_client_id = form.client_id.as_deref().filter(|c| !c.trim().is_empty());
        let (client_id, credential) = if let Some(encoded) = basic {
            let (id, secret) = decode_basic(encoded)?;
            if form_client_id.is_some_and(|form_id| form_id != id) {
                return Err(OAuthError::new(
                    "invalid_request",
                    "client_id does not name the client in the Authorization header",
                ));
            }
            (id, Credential::Basic(secret))
        } else if assertion_sent {
            let assertion = client_assertion(form)?;
            // RFC 7523 §3: `sub` names the client when `client_id` is absent.
            let id = match form_client_id {
                Some(id) => id.to_owned(),
                None => unverified_claim_str(assertion, "sub").ok_or_else(|| {
                    OAuthError::invalid_client(
                        "client_assertion names no client: its sub must be the client_id",
                        false,
                    )
                })?,
            };
            (id, Credential::Assertion(assertion))
        } else {
            let id = form_client_id
                .ok_or_else(|| OAuthError::invalid_client("client authentication required", false))?
                .to_owned();
            match form_secret {
                Some(secret) => (id, Credential::Post(secret.to_owned())),
                None => (id, Credential::Nothing),
            }
        };
        let client = self.client(&client_id, &credential).await?;
        self.check_credential(&client, credential).await?;
        Ok(client)
    }

    /// The client `client_id` names: a registered one, a dynamically
    /// registered one while registration is offered, else the one its
    /// metadata document describes.
    async fn client(
        &self,
        client_id: &str,
        credential: &Credential<'_>,
    ) -> Result<Arc<Client>, OAuthError> {
        let basic_attempted = matches!(credential, Credential::Basic(_));
        if let Some(client) = self.clients.iter().find(|c| c.client_id == client_id) {
            return Ok(Arc::clone(client));
        }
        if client_id.starts_with(DCR_CLIENT_ID_PREFIX) && self.registers_clients() {
            // Refused before the store is read: such a client holds no
            // credential.
            if !matches!(credential, Credential::Nothing) {
                return Err(OAuthError::invalid_client(
                    "a dynamically registered client is public: it authenticates with its \
                     client_id alone, without a secret or an assertion",
                    basic_attempted,
                ));
            }
            return match self.registered_client(client_id).await {
                Ok(Some(client)) => Ok(Arc::new(client)),
                Ok(None) => Err(OAuthError::invalid_client(
                    "unknown client: its registration expired or was removed; register again",
                    basic_attempted,
                )),
                Err(error) => {
                    tracing::error!(error = %error, "a client registration could not be read");
                    Err(OAuthError::temporarily_unavailable(
                        "the client's registration cannot be read right now; retry shortly",
                    ))
                }
            };
        }
        let Some(documents) = self
            .client_metadata
            .as_ref()
            .filter(|documents| documents.admits(client_id))
        else {
            return Err(OAuthError::invalid_client(
                "unknown client",
                basic_attempted,
            ));
        };
        // Never fetched for a credential such a client cannot hold.
        if matches!(credential, Credential::Basic(_) | Credential::Post(_)) {
            return Err(OAuthError::invalid_client(
                "a client identified by its metadata document cannot authenticate with a shared \
                 secret",
                basic_attempted,
            ));
        }
        // Checked before anything is cached or logged under the URL.
        if let Some(problem) =
            client_id_url_problem(client_id, documents.config.allow_private_network)
        {
            return Err(OAuthError::invalid_client(
                format!("the client_id {problem}"),
                false,
            ));
        }
        self.client_from_document(documents, client_id).await
    }

    async fn check_credential(
        &self,
        client: &Client,
        credential: Credential<'_>,
    ) -> Result<(), OAuthError> {
        let basic_attempted = matches!(credential, Credential::Basic(_));
        let refused = |description: &str| OAuthError::invalid_client(description, basic_attempted);
        match (&client.auth, credential) {
            (
                ClientAuth::Secret {
                    secret,
                    basic,
                    post,
                },
                Credential::Basic(presented) | Credential::Post(presented),
            ) => {
                if basic_attempted && !basic {
                    return Err(refused(
                        "client uses client_secret_post: send client_id and client_secret as \
                         form fields",
                    ));
                }
                if !basic_attempted && !post {
                    return Err(refused(
                        "client uses client_secret_basic: send its credentials in the \
                         Authorization header",
                    ));
                }
                if ct_eq(secret, &presented) {
                    Ok(())
                } else {
                    Err(refused("client authentication failed"))
                }
            }
            (ClientAuth::Secret { .. }, Credential::Assertion(_)) => Err(refused(
                "client authenticates with its client_secret, not a client_assertion",
            )),
            (ClientAuth::Secret { .. }, Credential::Nothing) => Err(refused(
                "client authentication required: this client authenticates with its client_secret",
            )),
            (
                ClientAuth::PrivateKeyJwt {
                    keys,
                    accept_token_endpoint_audience,
                },
                Credential::Assertion(assertion),
            ) => {
                self.verify_client_assertion(
                    &client.client_id,
                    keys,
                    *accept_token_endpoint_audience,
                    assertion,
                )
                .await
            }
            (ClientAuth::PrivateKeyJwt { .. }, _) => Err(refused(
                "client uses private_key_jwt: authenticate with a client_assertion",
            )),
            (ClientAuth::Public, Credential::Nothing) => Ok(()),
            (ClientAuth::Public, Credential::Assertion(_)) => Err(refused(
                "client is a public client (token_endpoint_auth_method none) and cannot present a \
                 client_assertion",
            )),
            // A stray secret is refused rather than silently ignored.
            (ClientAuth::Public, _) => Err(refused("client is registered without a secret")),
        }
    }

    /// Verify a `private_key_jwt` assertion for `client_id` (RFC 7523 §3):
    /// signed by one of the client's keys, `iss` = `sub` = the client, `aud`
    /// this issuer as its only value, `exp` at most
    /// [`MAX_CLIENT_ASSERTION_LIFETIME_SECS`] ahead, and a `jti` accepted
    /// once.
    async fn verify_client_assertion(
        &self,
        client_id: &str,
        keys: &ClientKeys,
        accept_token_endpoint_audience: bool,
        assertion: &str,
    ) -> Result<(), OAuthError> {
        let refused = |description: String| OAuthError::invalid_client(description, false);
        let header = jsonwebtoken::decode_header(assertion)
            .map_err(|_| refused("client_assertion is not a well-formed JWT".to_owned()))?;
        if !CLIENT_ASSERTION_ALGS
            .iter()
            .any(|(alg, _)| *alg == header.alg)
        {
            return Err(refused(format!(
                "client_assertion alg {:?} is not accepted; sign it with one of {}",
                header.alg,
                CLIENT_ASSERTION_ALGS
                    .iter()
                    .map(|(_, name)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        // RFC 8725 §3.11: a JWT typed as something else is not a client
        // assertion, whoever signed it.
        if let Some(ref typ) = header.typ
            && ![
                "JWT",
                "client-authentication+jwt",
                "application/client-authentication+jwt",
            ]
            .iter()
            .any(|accepted| typ.eq_ignore_ascii_case(accepted))
        {
            return Err(refused(
                "client_assertion typ is neither JWT nor client-authentication+jwt".to_owned(),
            ));
        }
        let key = self
            .client_key(client_id, keys, header.kid.as_deref(), header.alg)
            .await?;
        let token_endpoint = self.endpoint(TOKEN_PATH);
        let mut audiences = vec![self.issuer.as_str()];
        if accept_token_endpoint_audience {
            audiences.push(&token_endpoint);
        }
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.leeway_secs;
        validation.validate_nbf = true;
        validation.set_audience(&audiences);
        validation.set_issuer(&[client_id]);
        validation.sub = Some(client_id.to_owned());
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
        let claims = jsonwebtoken::decode::<ClientAssertionClaims>(assertion, &key, &validation)
            .map_err(|e| refused(self.client_assertion_problem(&e, &audiences)))?
            .claims;
        // rfc7523bis: the audience is the sole value, so an assertion made
        // for another server cannot also be presented here.
        if claims.aud.values().len() != 1 {
            return Err(refused(format!(
                "client_assertion aud must carry exactly one value, {}",
                audience_rule(&audiences)
            )));
        }
        let now = now_unix();
        if claims.exp > now + MAX_CLIENT_ASSERTION_LIFETIME_SECS + self.leeway_secs {
            return Err(refused(format!(
                "client_assertion exp lies more than {MAX_CLIENT_ASSERTION_LIFETIME_SECS} s ahead; \
                 sign a short-lived assertion for each request"
            )));
        }
        if claims.iat.is_some_and(|iat| iat > now + self.leeway_secs) {
            return Err(refused("client_assertion iat is in the future".to_owned()));
        }
        let jti = claims
            .jti
            .filter(|jti| !jti.is_empty())
            .ok_or_else(|| refused("client_assertion carries no jti".to_owned()))?;
        if self
            .claim_once(&client_assertion_key(client_id, &jti), claims.exp)
            .await?
        {
            Ok(())
        } else {
            Err(refused(
                "client_assertion has already been used; sign a new one for each request"
                    .to_owned(),
            ))
        }
    }

    /// The key of `client_id` that verifies an assertion with `kid`/`alg`.
    async fn client_key(
        &self,
        client_id: &str,
        keys: &ClientKeys,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, OAuthError> {
        let resolved = match keys {
            ClientKeys::Inline(set) => select_key(set, kid, alg).and_then(|key| {
                key.ok_or(KeyError::NoMatch("no key of the client matches the kid"))
            }),
            ClientKeys::Remote {
                uri,
                allowed_hosts,
                allow_private,
                cache,
            } => {
                cache
                    .key_for(KeyOwner::Client(client_id), kid, alg, || {
                        fetch_client_jwks(uri, allowed_hosts, *allow_private)
                    })
                    .await
            }
        };
        resolved.map_err(|error| {
            tracing::debug!(client_id = %client_id, error = ?error, "client key resolution failed");
            match error {
                KeyError::NoMatch(reason) => OAuthError::invalid_client(
                    format!("client_assertion signature key could not be resolved: {reason}"),
                    false,
                ),
                KeyError::Unavailable => OAuthError::temporarily_unavailable(
                    "the client's signing keys cannot be fetched right now; retry shortly",
                ),
                KeyError::Misconfigured(reason) => OAuthError::invalid_client(
                    format!("the client's signing keys cannot be used: {reason}"),
                    false,
                ),
            }
        })
    }

    /// What the decoder refused in a client assertion.
    fn client_assertion_problem(
        &self,
        error: &jsonwebtoken::errors::Error,
        audiences: &[&str],
    ) -> String {
        match error.kind() {
            ErrorKind::InvalidAudience => {
                format!(
                    "client_assertion aud is wrong: {}",
                    audience_rule(audiences)
                )
            }
            ErrorKind::InvalidIssuer | ErrorKind::InvalidSubject => {
                "client_assertion iss and sub must both be the client_id".to_owned()
            }
            ErrorKind::ExpiredSignature => "client_assertion has expired".to_owned(),
            ErrorKind::ImmatureSignature => "client_assertion is not valid yet (nbf)".to_owned(),
            ErrorKind::InvalidSignature => "client_assertion signature is invalid".to_owned(),
            ErrorKind::MissingRequiredClaim(claim) => {
                format!("client_assertion carries no `{claim}` claim")
            }
            _ => format!("client_assertion validation failed: {error}"),
        }
    }

    /// The client a metadata document at `url` describes, for client
    /// authentication at the token endpoint.
    async fn client_from_document(
        &self,
        documents: &ClientMetadataDocuments,
        url: &str,
    ) -> Result<Arc<Client>, OAuthError> {
        match documents.client(url, DocumentUse::Token).await {
            Ok((client, _)) => Ok(client),
            Err(DocumentProblem::Rejected(reason)) => Err(OAuthError::invalid_client(
                format!("the client metadata document at {url} is refused: {reason}"),
                false,
            )),
            Err(DocumentProblem::Unavailable) => Err(OAuthError::temporarily_unavailable(format!(
                "the client metadata document at {url} cannot be fetched right now; retry shortly"
            ))),
        }
    }

    /// The client of an authorization request that names `client_id` and
    /// `redirect_uri` (empty values count as absent): a registered client,
    /// a dynamically registered one while registration is offered, else
    /// the one a fresh metadata document describes. When the requested
    /// redirect URI is missing from a cached document, the document is
    /// fetched again once, within the retry spacing.
    pub async fn authorize_client(
        &self,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<AuthorizeClient, AuthorizeClientError> {
        let client_id = client_id
            .filter(|id| !id.is_empty())
            .ok_or(AuthorizeClientError::MissingClientId)?;
        if let Some(client) = self.clients.iter().find(|c| c.client_id == client_id) {
            return client.authorize(redirect_uri);
        }
        if client_id.starts_with(DCR_CLIENT_ID_PREFIX) && self.registers_clients() {
            return match self.registered_client(client_id).await {
                Ok(Some(client)) => client.authorize(redirect_uri),
                Ok(None) => Err(AuthorizeClientError::UnknownClient),
                Err(error) => {
                    tracing::error!(error = %error, "a client registration could not be read");
                    Err(AuthorizeClientError::RegistrationUnavailable)
                }
            };
        }
        let Some(documents) = self
            .client_metadata
            .as_ref()
            .filter(|documents| documents.admits(client_id))
        else {
            return Err(AuthorizeClientError::UnknownClient);
        };
        // Checked before anything is cached or logged under the URL.
        if let Some(problem) =
            client_id_url_problem(client_id, documents.config.allow_private_network)
        {
            return Err(AuthorizeClientError::InvalidDocument(format!(
                "the client_id {problem}"
            )));
        }
        let (client, fetched) = documents
            .client(client_id, DocumentUse::Authorize)
            .await
            .map_err(DocumentProblem::for_authorize)?;
        match client.authorize(redirect_uri) {
            Err(AuthorizeClientError::Redirect(
                RedirectError::NotRegistered | RedirectError::Refused(_),
            )) if !fetched => documents
                .client(client_id, DocumentUse::AuthorizeRefetch)
                .await
                .map_err(DocumentProblem::for_authorize)?
                .0
                .authorize(redirect_uri),
            resolved => resolved,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    aud: StringOrVec,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
}

/// The `aud` a client assertion must carry, for an error description.
fn audience_rule(audiences: &[&str]) -> String {
    match audiences {
        [issuer] => format!("it must be this authorization server's issuer, `{issuer}`"),
        [issuer, token_endpoint, ..] => format!(
            "it must be this authorization server's issuer, `{issuer}`, or its token endpoint, \
             `{token_endpoint}`"
        ),
        [] => String::new(),
    }
}

/// Ledger key of a used client assertion; hashed like an ID-JAG's.
fn client_assertion_key(client_id: &str, jti: &str) -> String {
    let mut hasher =
        blake3::Hasher::new_derive_key("mcpg ema client-assertion single-use ledger v1");
    hasher.update(&(client_id.len() as u64).to_le_bytes());
    hasher.update(client_id.as_bytes());
    hasher.update(jti.as_bytes());
    format!(
        "{CLIENT_ASSERTION_KEY_PREFIX}{}",
        hasher.finalize().to_hex()
    )
}

/// RFC 6749 §2.3.1: Basic credentials are form-urlencoded before base64.
fn decode_basic(encoded: &str) -> Result<(String, String), OAuthError> {
    let malformed = || OAuthError::invalid_client("malformed Basic credentials", true);
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| malformed())?;
    let decoded = String::from_utf8(decoded).map_err(|_| malformed())?;
    let (id, secret) = decoded.split_once(':').ok_or_else(malformed)?;
    Ok((
        percent_decode(id).ok_or_else(malformed)?,
        percent_decode(secret).ok_or_else(malformed)?,
    ))
}

/// The `client_assertion` of a `private_key_jwt` request.
fn client_assertion(form: &TokenRequestForm) -> Result<&str, OAuthError> {
    let assertion = form
        .client_assertion
        .as_deref()
        .filter(|assertion| !assertion.trim().is_empty());
    match (form.client_assertion_type.as_deref(), assertion) {
        (Some(CLIENT_ASSERTION_TYPE_JWT_BEARER), Some(assertion)) => Ok(assertion),
        (None, _) => Err(OAuthError::new(
            "invalid_request",
            "client_assertion requires client_assertion_type",
        )),
        (Some(_), None) => Err(OAuthError::new(
            "invalid_request",
            "client_assertion_type requires a client_assertion",
        )),
        (Some(_), Some(_)) => Err(OAuthError::invalid_client(
            format!(
                "unsupported client_assertion_type; the one accepted is \
                 {CLIENT_ASSERTION_TYPE_JWT_BEARER}"
            ),
            false,
        )),
    }
}

// ── Client ID Metadata Documents ─────────────────────────────────────

/// Clients identified by the URL of their metadata document.
pub(super) struct ClientMetadataDocuments {
    config: ClientIdMetadataDocumentsConfig,
    slots: Mutex<HashMap<String, Arc<DocumentSlot>>>,
}

struct DocumentSlot {
    /// Held across a fetch, so concurrent requests share it.
    state: tokio::sync::Mutex<DocumentState>,
    used_at: Mutex<Instant>,
}

#[derive(Default)]
struct DocumentState {
    document: Option<CachedDocument>,
    last_attempt: Option<Instant>,
    /// Why the last fetch failed, until one succeeds.
    failure: Option<DocumentFailure>,
}

struct CachedDocument {
    client: Arc<Client>,
    fetched_at: Instant,
    fresh_for: Duration,
}

impl CachedDocument {
    fn is_fresh(&self) -> bool {
        self.fetched_at.elapsed() < self.fresh_for
    }
}

enum DocumentFailure {
    Unavailable,
    Rejected(String),
}

/// What a document is read for, which decides how old it may be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DocumentUse {
    /// Client authentication: the last document that validated serves for
    /// up to [`CLIENT_METADATA_MAX_STALENESS`] while its host cannot be
    /// reached.
    Token,
    /// The authorization endpoint: only a fresh document, whose redirect
    /// URIs the client's host still stands behind.
    Authorize,
    /// The authorization endpoint after a requested redirect URI was
    /// missing from the cached document (CIMD §8.4): fetched again when
    /// the retry spacing allows, else the fresh cached one.
    AuthorizeRefetch,
}

/// Why no document serves.
enum DocumentProblem {
    /// The document is refused; the text says why.
    Rejected(String),
    /// It cannot be fetched now, and no copy that may serve is cached.
    Unavailable,
}

impl DocumentProblem {
    fn for_authorize(self) -> AuthorizeClientError {
        match self {
            Self::Rejected(reason) => AuthorizeClientError::InvalidDocument(reason),
            Self::Unavailable => AuthorizeClientError::DocumentUnavailable,
        }
    }
}

impl ClientMetadataDocuments {
    pub(super) fn new(config: ClientIdMetadataDocumentsConfig) -> Self {
        Self {
            config,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// The client the document at `url` describes, and whether this call
    /// fetched it. A document is fetched at most once per
    /// [`CLIENT_METADATA_RETRY_INTERVAL`], and reused while fresh; `usage`
    /// decides whether an older one serves.
    async fn client(
        &self,
        url: &str,
        usage: DocumentUse,
    ) -> Result<(Arc<Client>, bool), DocumentProblem> {
        let slot = self.slot(url);
        let mut state = slot.state.lock().await;
        if usage != DocumentUse::AuthorizeRefetch
            && let Some(ref cached) = state.document
            && cached.is_fresh()
        {
            return Ok((Arc::clone(&cached.client), false));
        }
        if state
            .last_attempt
            .is_none_or(|at| at.elapsed() >= CLIENT_METADATA_RETRY_INTERVAL)
        {
            state.last_attempt = Some(Instant::now());
            match fetch_client_metadata(url, &self.config).await {
                Ok((client, fresh_for)) => {
                    count_document_fetch("ok");
                    let client = Arc::new(client);
                    state.document = Some(CachedDocument {
                        client: Arc::clone(&client),
                        fetched_at: Instant::now(),
                        fresh_for,
                    });
                    state.failure = None;
                    return Ok((client, true));
                }
                Err(FetchFailure::Transient(error)) => {
                    count_document_fetch("failed");
                    tracing::warn!(
                        client_id = %url,
                        error = %format!("{error:#}"),
                        cached_document = state.document.is_some(),
                        "client metadata document could not be fetched"
                    );
                    state.failure = Some(DocumentFailure::Unavailable);
                }
                Err(FetchFailure::Rejected(reason)) => {
                    count_document_fetch("rejected");
                    tracing::warn!(
                        client_id = %url,
                        reason = %reason,
                        "client metadata document refused"
                    );
                    state.document = None;
                    state.failure = Some(DocumentFailure::Rejected(reason));
                }
            }
        }
        match (&state.failure, &state.document) {
            (Some(DocumentFailure::Rejected(reason)), _) => {
                Err(DocumentProblem::Rejected(reason.clone()))
            }
            (_, Some(cached))
                if cached.is_fresh()
                    || (usage == DocumentUse::Token
                        && cached.fetched_at.elapsed() < CLIENT_METADATA_MAX_STALENESS) =>
            {
                Ok((Arc::clone(&cached.client), false))
            }
            _ => Err(DocumentProblem::Unavailable),
        }
    }

    /// Whether any unregistered client can identify with a document.
    pub(super) fn admits_unregistered(&self) -> bool {
        !self.config.allowed_hosts.is_empty()
    }

    /// Whether `client_id` is a document URL this configuration resolves.
    pub(super) fn admits(&self, client_id: &str) -> bool {
        self.config.admits(client_id)
    }

    fn slot(&self, url: &str) -> Arc<DocumentSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = slots.get(url) {
            *slot.used_at.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
            return Arc::clone(slot);
        }
        if slots.len() >= MAX_CACHED_CLIENT_METADATA {
            // A slot a request still holds is never evicted.
            let idle = slots
                .iter()
                .filter(|(_, slot)| Arc::strong_count(slot) == 1)
                .min_by_key(|(_, slot)| *slot.used_at.lock().unwrap_or_else(|p| p.into_inner()))
                .map(|(url, _)| url.clone());
            if let Some(idle) = idle {
                slots.remove(&idle);
            }
        }
        let slot = Arc::new(DocumentSlot {
            state: tokio::sync::Mutex::new(DocumentState::default()),
            used_at: Mutex::new(Instant::now()),
        });
        slots.insert(url.to_owned(), Arc::clone(&slot));
        slot
    }
}

#[cfg(test)]
impl ClientMetadataDocuments {
    /// Make the cached document of `url` `age` older, and let the next
    /// request refetch it at once.
    pub(super) async fn age_document(&self, url: &str, age: Duration) {
        let slot = self.slot(url);
        let mut state = slot.state.lock().await;
        if let Some(ref mut document) = state.document {
            document.fetched_at = document
                .fetched_at
                .checked_sub(age)
                .expect("monotonic clock is past the age");
        }
        state.last_attempt = None;
    }
}

/// The members of a metadata document this server reads. The ones only
/// the authorization endpoint needs are read loosely, so a document that
/// authenticates a client at the token endpoint keeps doing so whatever
/// they hold.
#[derive(Deserialize)]
struct ClientMetadataDocument {
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    #[serde(default)]
    jwks: Option<serde_json::Value>,
    #[serde(default)]
    client_secret: Option<serde_json::Value>,
    #[serde(default)]
    redirect_uris: Option<serde_json::Value>,
    #[serde(default)]
    client_name: Option<serde_json::Value>,
    #[serde(default)]
    grant_types: Option<serde_json::Value>,
    #[serde(default)]
    response_types: Option<serde_json::Value>,
    #[serde(default)]
    application_type: Option<serde_json::Value>,
    #[serde(default)]
    dpop_bound_access_tokens: Option<serde_json::Value>,
}

fn count_document_fetch(outcome: &'static str) {
    metrics::counter!("mcpg_ema_client_metadata_fetch_total", "outcome" => outcome).increment(1);
}

/// Fetch and validate the metadata document at `url`: the client it
/// describes, and how long the document may be reused.
async fn fetch_client_metadata(
    url: &str,
    config: &ClientIdMetadataDocumentsConfig,
) -> Result<(Client, Duration), FetchFailure> {
    if let Some(problem) = client_id_url_problem(url, config.allow_private_network) {
        return Err(FetchFailure::Rejected(format!("the client_id {problem}")));
    }
    enforce_discovery_url_safety(url, &config.allowed_hosts, config.allow_private_network)
        .map_err(|e| FetchFailure::Rejected(format!("the document URL is refused: {e}")))?;
    let (headers, body) =
        fetch_pinned(url, config.allow_private_network, MAX_CLIENT_METADATA_BYTES).await?;
    if !is_json_media_type(&headers) {
        return Err(FetchFailure::Rejected(
            "it is not served as application/json".to_owned(),
        ));
    }
    let client = client_from_document_body(url, &body, config)?;
    let refused = client.interactive.redirects.refused();
    if !refused.is_empty() {
        tracing::warn!(
            client_id = %url,
            refused = ?refused,
            "client metadata document lists redirect URIs this server refuses; they never match"
        );
    }
    Ok((client, document_lifetime(&headers)))
}

/// The client the metadata document `body`, served at `url`, describes.
pub(super) fn client_from_document_body(
    url: &str,
    body: &[u8],
    config: &ClientIdMetadataDocumentsConfig,
) -> Result<Client, FetchFailure> {
    let not_a_document =
        |e: String| FetchFailure::Rejected(format!("it is not a client metadata document: {e}"));
    let document: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| not_a_document(e.to_string()))?;
    // A derived struct also reads a JSON array, positionally.
    if !document.is_object() {
        return Err(not_a_document("the body is not a JSON object".to_owned()));
    }
    let document: ClientMetadataDocument =
        serde_json::from_value(document).map_err(|e| not_a_document(e.to_string()))?;
    match document.client_id.as_deref() {
        Some(client_id) if client_id == url => {}
        Some(client_id) => {
            return Err(FetchFailure::Rejected(format!(
                "its client_id {} is not the document URL; the two must be equal",
                echo(client_id)
            )));
        }
        None => {
            return Err(FetchFailure::Rejected("it carries no client_id".to_owned()));
        }
    }
    if document.client_secret.is_some() {
        return Err(FetchFailure::Rejected(
            "it carries a client_secret, and a metadata document client cannot use a shared \
             secret"
                .to_owned(),
        ));
    }
    let interactive = InteractiveProfile::from_document(url, &document, config);
    // A document that publishes keys but names no method authenticates
    // with them, as a registered client does: read as public, anyone
    // holding one of its ID-JAGs could redeem it without the key.
    let publishes_keys = document.jwks.is_some() || document.jwks_uri.is_some();
    let auth = match document.token_endpoint_auth_method.as_deref() {
        None if !publishes_keys => ClientAuth::Public,
        Some("none") => ClientAuth::Public,
        None | Some("private_key_jwt") => {
            let keys = match (document.jwks, document.jwks_uri) {
                (Some(jwks), None) => ClientKeys::Inline(
                    parse_public_jwks(&jwks)
                        .map_err(|e| FetchFailure::Rejected(format!("its jwks {e}")))?,
                ),
                (None, Some(uri)) => {
                    enforce_discovery_url_safety(
                        &uri,
                        &config.allowed_hosts,
                        config.allow_private_network,
                    )
                    .map_err(|e| FetchFailure::Rejected(format!("its jwks_uri is refused: {e}")))?;
                    ClientKeys::Remote {
                        uri,
                        allowed_hosts: config.allowed_hosts.clone(),
                        allow_private: config.allow_private_network,
                        cache: KeyCache::default(),
                    }
                }
                (Some(_), Some(_)) => {
                    return Err(FetchFailure::Rejected(
                        "it sets both jwks and jwks_uri; RFC 7591 allows one".to_owned(),
                    ));
                }
                (None, None) => {
                    return Err(FetchFailure::Rejected(
                        "it declares private_key_jwt without jwks or jwks_uri".to_owned(),
                    ));
                }
            };
            ClientAuth::PrivateKeyJwt {
                keys,
                accept_token_endpoint_audience: false,
            }
        }
        Some(method @ ("client_secret_basic" | "client_secret_post" | "client_secret_jwt")) => {
            return Err(FetchFailure::Rejected(format!(
                "it declares {method}, and a metadata document client cannot use a shared secret"
            )));
        }
        Some(other) => {
            return Err(FetchFailure::Rejected(format!(
                "it declares token_endpoint_auth_method {}, which this server does not support",
                echo(other)
            )));
        }
    };
    // A malformed value counts as `true`, the stricter reading.
    let dpop_bound_access_tokens = document
        .dpop_bound_access_tokens
        .as_ref()
        .is_some_and(|value| *value != serde_json::Value::Bool(false));
    Ok(Client {
        client_id: url.to_owned(),
        auth,
        interactive,
        redeems_id_jags: true,
        dpop_bound_access_tokens,
    })
}

/// Why `url` cannot be a client identifier: the draft requires an `https`
/// URL with a path and no dot segments, fragment or userinfo. It must also
/// be the URL the fetch requests, character for character: a parser
/// rewrites encoded dot segments, `\`, control characters, an upper-case
/// host and a default port.
pub(super) fn client_id_url_problem(url: &str, allow_http: bool) -> Option<&'static str> {
    if url.len() > MAX_CLIENT_ID_URL_BYTES {
        return Some("is too long");
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return Some("is not a URL");
    };
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        _ => return Some("must be an https URL"),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("must not carry userinfo");
    }
    if url.contains('#') {
        return Some("must not carry a fragment");
    }
    // Checked on the text, since parsing resolves dot segments away.
    let after_scheme = url.split_once("://").map_or("", |(_, rest)| rest);
    let Some(path_start) = after_scheme.find('/') else {
        return Some("must have a path");
    };
    let path = after_scheme[path_start..]
        .split('?')
        .next()
        .unwrap_or_default();
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Some("must not contain `.` or `..` path segments");
    }
    if parsed.as_str() != url {
        return Some(
            "must be in canonical form: a lower-case host, no default port, no backslash or \
             control characters, and no encoded `.` or `..` path segments",
        );
    }
    None
}

fn is_json_media_type(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|media| {
            media == "application/json"
                || (media.starts_with("application/") && media.ends_with("+json"))
        })
}

/// How long a document may be reused: its `Cache-Control: max-age`, or
/// the floor under `no-cache`/`no-store`, within the TTL bounds.
pub(super) fn document_lifetime(headers: &reqwest::header::HeaderMap) -> Duration {
    let mut max_age = None;
    let mut uncacheable = false;
    for directive in headers
        .get_all(reqwest::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        let directive = directive.trim();
        if directive.eq_ignore_ascii_case("no-store") || directive.eq_ignore_ascii_case("no-cache")
        {
            uncacheable = true;
        } else if let Some((name, value)) = directive.split_once('=')
            && name.trim().eq_ignore_ascii_case("max-age")
        {
            max_age = value.trim().trim_matches('"').parse::<u64>().ok();
        }
    }
    let lifetime = if uncacheable {
        Duration::ZERO
    } else {
        max_age.map_or(CLIENT_METADATA_DEFAULT_TTL, Duration::from_secs)
    };
    lifetime.clamp(CLIENT_METADATA_MIN_TTL, CLIENT_METADATA_MAX_TTL)
}

/// A client-supplied value, quoted and cut to [`ECHO_LIMIT`] characters for
/// an error description.
pub(super) fn echo(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_owned()).to_string();
    if quoted.chars().count() > ECHO_LIMIT {
        format!("{}…", quoted.chars().take(ECHO_LIMIT).collect::<String>())
    } else {
        quoted
    }
}

/// A `private_key_jwt` client's key set from `uri`.
async fn fetch_client_jwks(
    uri: &str,
    allowed_hosts: &[String],
    allow_private: bool,
) -> Result<JwkSet, FetchFailure> {
    enforce_discovery_url_safety(uri, allowed_hosts, allow_private)
        .map_err(|e| FetchFailure::Rejected(format!("the key URL is refused: {e}")))?;
    let (_, body) = fetch_pinned(uri, allow_private, MAX_IDP_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body).map_err(|e| {
        FetchFailure::Transient(anyhow::anyhow!("parsing the client JWKS from {uri}: {e}"))
    })
}

/// GET `url`, which a client chose, over a pinned client (the host is
/// resolved first and refused when any address is private, unless
/// `allow_private`; no redirect is followed), reading at most `max_bytes`
/// of the body. A client error, a redirect or an oversized body is
/// `Rejected`; a network or server failure, a timeout or a rate limit is
/// `Transient`.
async fn fetch_pinned(
    url: &str,
    allow_private: bool,
    max_bytes: usize,
) -> Result<(reqwest::header::HeaderMap, Vec<u8>), FetchFailure> {
    let (http, parsed) = pinned_client(url, allow_private, CLIENT_FETCH_TIMEOUT).await?;
    let mut response = http
        .get(parsed)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| FetchFailure::Transient(anyhow::anyhow!("fetching {url}: {e}")))?;
    check_answering_address(&response, url, allow_private)?;
    let status = response.status();
    if !status.is_success() {
        return Err(status_failure(url, status));
    }
    let headers = response.headers().clone();
    let body = read_capped(&mut response, url, max_bytes).await?;
    Ok((headers, body))
}
