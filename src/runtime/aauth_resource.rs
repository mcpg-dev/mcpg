//! The gateway's AAuth *Resource* role beyond identity verification.
//!
//! The `dev.mcpg.identity.aauth` plugin verifies what an agent presents. This
//! module is what a resource must DO in the authorization modes: publish a
//! signing key, mint the resource tokens a person server turns into auth
//! tokens, and honour the revocations that person server sends back. It is
//! built once from `server.aauth_resource_metadata` and shared behind the
//! runtime.
//!
//! State kept here is process-local: revocations reach the replica that
//! received them and expire with the token they name (≤ 1 h for auth tokens),
//! which is the exposure bound the protocol itself relies on.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mcpg_aauth_core as aauth;
use mcpg_aauth_core::jwk::{Jwk, Jwks, SigningKey};
use mcpg_aauth_core::sig::{self, RequestParts, SigError, SigErrorCode, VerifyPolicy};
use mcpg_aauth_core::sigkey::SigKeyScheme;
use mcpg_aauth_core::tokens::{self, ResourceTokenRequest};

use crate::config::{AauthResourceMetadataConfig, AauthSigningKeyConfig};
use crate::runtime::RequestIdentity;

/// Well-known paths this module serves under the resource identifier.
pub const JWKS_PATH: &str = "/.well-known/aauth-jwks.json";
pub const AUTHORIZE_PATH: &str = "/aauth/authorize";
pub const REVOKE_PATH: &str = "/aauth/revoke";

/// Attribute keys the identity plugin sets on every AAuth identity.
pub const ATTR_TOKEN_TYPE: &str = "aauth.token_type";
pub const ATTR_JTI: &str = "aauth.jti";
pub const ATTR_PS: &str = "aauth.ps";
pub const ATTR_AGENT_JKT: &str = "aauth.agent_jkt";
pub const ATTR_EXP: &str = "aauth.exp";
pub const ATTR_MISSION: &str = "aauth.mission_s256";
pub const ATTR_TENANT: &str = "aauth.tenant";
pub const ATTR_ACCOUNT: &str = "aauth.account";

/// Bound on remembered revocations / person presentations. Both sets are
/// keyed by attacker-influenced strings; on overflow expired entries are
/// pruned and, if still full, the set is cleared (a brief loss of the
/// optimisation each provides, never a false acceptance).
const MAX_ENTRIES: usize = 65_536;

/// Cache of person-server keys used to verify revocation requests: fetch
/// floor and ceiling mirror the identity plugin's.
const PS_KEYS_FLOOR: Duration = Duration::from_secs(60);
const PS_KEYS_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const FETCH_MAX_BYTES: usize = 64 * 1024;

/// The identity-plugin `scope`-less credential kinds a resource token can be
/// minted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AauthTokenType {
    Agent,
    Person,
    Auth,
}

impl AauthTokenType {
    pub fn of(identity: &RequestIdentity) -> Option<Self> {
        match identity
            .attributes()
            .get(ATTR_TOKEN_TYPE)
            .map(String::as_str)
        {
            Some("agent") => Some(Self::Agent),
            Some("person") => Some(Self::Person),
            Some("auth") => Some(Self::Auth),
            _ => None,
        }
    }
}

/// Why a resource token could not be minted for this caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRefusal {
    /// The gateway publishes no signing key (metadata declares an
    /// identity-only `access_mode`).
    NoSigningKey,
    /// The caller is not an AAuth person (or auth-token) identity — the
    /// protocol requires a verified person token before a resource token.
    PersonTokenRequired,
    /// A requested scope is not one this resource declares.
    UnknownScope(String),
}

/// A person token this replica verified recently — what a later step-up
/// (a caller presenting an auth token) needs to name as `presented_jti`.
struct PersonPresentation {
    jti: String,
    mission_s256: Option<String>,
    tenant: Option<String>,
    expires_at: u64,
}

pub struct AauthResource {
    config: AauthResourceMetadataConfig,
    signing: Option<(SigningKey, String)>,
    jwks_document: serde_json::Value,
    /// `(iss, jti)` → unix second after which the entry may be dropped.
    revoked: Mutex<HashMap<(String, String), u64>>,
    /// `(ps, sub, agent_jkt)` → the person token last presented.
    person_seen: Mutex<HashMap<(String, String, String), PersonPresentation>>,
    /// Person-server JWKS by issuer, for verifying revocation requests.
    ps_keys: Mutex<HashMap<String, (Jwks, Instant)>>,
    ps_last_attempt: Mutex<HashMap<String, Instant>>,
}

impl std::fmt::Debug for AauthResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AauthResource")
            .field("issuer", &self.config.issuer)
            .field("access_mode", &self.config.access_mode)
            .field("signing_kid", &self.signing.as_ref().map(|(_, kid)| kid))
            .finish()
    }
}

impl AauthResource {
    /// Build from config. Returns `None` when no AAuth resource metadata is
    /// configured. A signing key is required for `access_mode: auth-token`
    /// (the mode that mints resource tokens) and optional otherwise.
    pub fn from_config(config: &AauthResourceMetadataConfig) -> Result<Self> {
        let signing = match &config.signing_key {
            Some(k) => Some(load_signing_key(k)?),
            None if config.access_mode == "auth-token" => anyhow::bail!(
                "server.aauth_resource_metadata.access_mode is `auth-token` but no `signing_key` \
                 is configured — resource tokens must be signed with a key published at the \
                 gateway's jwks_uri (set signing_key.seed_file / seed, or `ephemeral: true` for \
                 development)"
            ),
            None => None,
        };
        let jwks_document = match &signing {
            Some((key, kid)) => {
                let mut jwk = Jwk::from_verifying_key(&key.verifying_key());
                jwk.kid = Some(kid.clone());
                jwk.use_ = Some("sig".to_owned());
                serde_json::json!({ "keys": [jwk] })
            }
            None => serde_json::json!({ "keys": [] }),
        };
        Ok(Self {
            config: config.clone(),
            signing,
            jwks_document,
            revoked: Mutex::new(HashMap::new()),
            person_seen: Mutex::new(HashMap::new()),
            ps_keys: Mutex::new(HashMap::new()),
            ps_last_attempt: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &AauthResourceMetadataConfig {
        &self.config
    }

    /// Whether resource tokens can be minted here.
    pub fn can_mint(&self) -> bool {
        self.signing.is_some()
    }

    /// The `{"keys": [...]}` document served at [`JWKS_PATH`].
    pub fn jwks_document(&self) -> &serde_json::Value {
        &self.jwks_document
    }

    /// The `/.well-known/aauth-resource.json` document, including the
    /// endpoints this module serves.
    pub fn metadata_document(&self) -> serde_json::Value {
        let mut doc = self.config.document();
        let iss = self.config.issuer.trim_end_matches('/');
        if let Some(obj) = doc.as_object_mut() {
            if self.signing.is_some() {
                obj.entry("jwks_uri")
                    .or_insert_with(|| format!("{iss}{JWKS_PATH}").into());
                obj.entry("authorization_endpoint")
                    .or_insert_with(|| format!("{iss}{AUTHORIZE_PATH}").into());
            }
            obj.entry("revocation_endpoint")
                .or_insert_with(|| format!("{iss}{REVOKE_PATH}").into());
        }
        doc
    }

    // -- resource tokens ---------------------------------------------------

    /// Remember the person token a verified person identity presented, so a
    /// later step-up from the auth token it produced can name it.
    pub fn record_identity(&self, identity: &RequestIdentity) {
        if AauthTokenType::of(identity) != Some(AauthTokenType::Person) {
            return;
        }
        let attrs = identity.attributes();
        let (Some(ps), Some(sub), Some(jkt), Some(jti)) = (
            attrs.get(ATTR_PS),
            identity.principal_id(),
            attrs.get(ATTR_AGENT_JKT),
            attrs.get(ATTR_JTI),
        ) else {
            return;
        };
        let expires_at = attrs
            .get(ATTR_EXP)
            .and_then(|e| e.parse::<u64>().ok())
            .unwrap_or_else(|| aauth::now_unix() + tokens::PERSON_TOKEN_MAX_TTL_SECS);
        let Ok(mut seen) = self.person_seen.lock() else {
            return;
        };
        if seen.len() >= MAX_ENTRIES {
            let now = aauth::now_unix();
            seen.retain(|_, p| p.expires_at > now);
            if seen.len() >= MAX_ENTRIES {
                seen.clear();
            }
        }
        seen.insert(
            (ps.clone(), sub.to_owned(), jkt.clone()),
            PersonPresentation {
                jti: jti.clone(),
                mission_s256: attrs.get(ATTR_MISSION).cloned(),
                tenant: attrs.get(ATTR_TENANT).cloned(),
                expires_at,
            },
        );
    }

    /// Whether every requested scope is one this resource declares in
    /// `scope_descriptions` (or a standard OpenID identity scope).
    fn check_scopes(&self, scopes: &[String]) -> Result<(), MintRefusal> {
        const IDENTITY_SCOPES: [&str; 5] = ["openid", "profile", "email", "address", "phone"];
        for s in scopes {
            if !self.config.scope_descriptions.contains_key(s)
                && !IDENTITY_SCOPES.contains(&s.as_str())
            {
                return Err(MintRefusal::UnknownScope(s.clone()));
            }
        }
        Ok(())
    }

    /// Mint a resource token for the person the caller acts for, requesting
    /// `scopes`. The caller must be an AAuth person identity (the protocol's
    /// requirement) or an auth-token identity whose person token this replica
    /// still remembers (step-up).
    pub fn mint_resource_token(
        &self,
        identity: &RequestIdentity,
        scopes: &[String],
        account: Option<&str>,
    ) -> Result<String, MintRefusal> {
        let Some((key, kid)) = &self.signing else {
            return Err(MintRefusal::NoSigningKey);
        };
        self.check_scopes(scopes)?;
        let attrs = identity.attributes();
        let (ps, sub, jkt) = match (
            attrs.get(ATTR_PS),
            identity.principal_id(),
            attrs.get(ATTR_AGENT_JKT),
        ) {
            (Some(ps), Some(sub), Some(jkt)) => (ps.clone(), sub.to_owned(), jkt.clone()),
            _ => return Err(MintRefusal::PersonTokenRequired),
        };
        let (presented_jti, mission, tenant) = match AauthTokenType::of(identity) {
            Some(AauthTokenType::Person) => (
                attrs
                    .get(ATTR_JTI)
                    .cloned()
                    .ok_or(MintRefusal::PersonTokenRequired)?,
                attrs.get(ATTR_MISSION).cloned(),
                attrs.get(ATTR_TENANT).cloned(),
            ),
            Some(AauthTokenType::Auth) => {
                let seen = self
                    .person_seen
                    .lock()
                    .map_err(|_| MintRefusal::PersonTokenRequired)?;
                let now = aauth::now_unix();
                match seen.get(&(ps.clone(), sub.clone(), jkt.clone())) {
                    Some(p) if p.expires_at > now => {
                        (p.jti.clone(), p.mission_s256.clone(), p.tenant.clone())
                    }
                    _ => return Err(MintRefusal::PersonTokenRequired),
                }
            }
            _ => return Err(MintRefusal::PersonTokenRequired),
        };
        let scope = scopes.join(" ");
        let (token, _) = tokens::issue_resource_token(
            &ResourceTokenRequest {
                resource: self.config.issuer.trim_end_matches('/'),
                aud: &ps,
                ps: &ps,
                sub: &sub,
                presented_jti: &presented_jti,
                agent_jkt: &jkt,
                scope: &scope,
                account,
                mission_s256: mission.as_deref(),
                tenant: tenant.as_deref(),
                ttl_secs: self.config.resource_token_ttl_secs,
            },
            kid,
            key,
            aauth::now_unix(),
        );
        Ok(token)
    }

    // -- revocation ------------------------------------------------------

    /// Record `(iss, jti)` as revoked until `expires_at` (unix seconds).
    pub fn revoke(&self, iss: &str, jti: &str, expires_at: u64) {
        let Ok(mut revoked) = self.revoked.lock() else {
            return;
        };
        if revoked.len() >= MAX_ENTRIES {
            let now = aauth::now_unix();
            revoked.retain(|_, exp| *exp > now);
            if revoked.len() >= MAX_ENTRIES {
                revoked.clear();
            }
        }
        revoked.insert((iss.to_owned(), jti.to_owned()), expires_at);
    }

    /// Whether the credential behind `identity` names a revoked `(iss, jti)`.
    pub fn is_revoked(&self, identity: &RequestIdentity) -> bool {
        let (Some(iss), Some(jti)) = (identity.issuer(), identity.attributes().get(ATTR_JTI))
        else {
            return false;
        };
        let Ok(revoked) = self.revoked.lock() else {
            return false;
        };
        matches!(
            revoked.get(&(iss.to_owned(), jti.clone())),
            Some(exp) if *exp > aauth::now_unix()
        )
    }

    /// Verify a `POST /aauth/revoke` request: signed by a server as itself
    /// (`Signature-Key` scheme `jwks_uri`) whose `id` MUST equal the `iss` of
    /// the token being revoked, covering `content-type` + `content-digest`
    /// over the JSON body. Returns the verified `(iss, jti)`.
    pub async fn verify_revocation(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(String, String), SigError> {
        // Everything that borrows the request is done before the first
        // await: `RequestParts` holds a `&dyn Fn`, which must not live across
        // the key fetch for the future to stay `Send`.
        let (parsed, id, dwk, kid, iss, jti) =
            self.parse_revocation(method, authority, path, query, headers, body)?;
        let key = self.ps_key(&id, &dwk, &kid).await?;
        if sig::verify_parsed(&parsed, &key).is_err() {
            // Silent re-key: refresh once and retry, floor-gated.
            let key = self.ps_key_refresh(&id, &dwk, &kid).await?;
            sig::verify_parsed(&parsed, &key)?;
        }
        Ok((iss, jti))
    }

    /// The synchronous half of [`Self::verify_revocation`]: signature
    /// structure, scheme, digest, and body — returning the parsed signature
    /// plus the signer identity and the `(iss, jti)` it names.
    #[allow(clippy::type_complexity)]
    fn parse_revocation(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(sig::ParsedSignature, String, String, String, String, String), SigError> {
        let header = |name: &str| -> Option<String> {
            let vals: Vec<&str> = headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
                .collect();
            (!vals.is_empty()).then(|| vals.join(", "))
        };
        let parts = RequestParts {
            method,
            authority,
            path,
            query,
            header: &header,
        };
        let policy = VerifyPolicy {
            now: aauth::now_unix(),
            window_secs: self.config.signature_window.unwrap_or(60),
            extra_required: vec!["content-type".to_owned(), "content-digest".to_owned()],
        };
        let parsed = sig::parse_request_signature(&parts, &policy)?;
        let (id, dwk, kid) = match &parsed.scheme {
            SigKeyScheme::JwksUri { id, dwk, kid } => (id.clone(), dwk.clone(), kid.clone()),
            _ => {
                return Err(SigError::new(
                    SigErrorCode::UnsupportedScheme,
                    "revocation requests are signed by a server as itself (scheme jwks_uri)",
                ));
            }
        };
        if !matches!(dwk.as_str(), "aauth-person.json" | "aauth-access.json") {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                "revocation signer dwk must be aauth-person.json or aauth-access.json",
            ));
        }
        aauth::ident::validate_server_identifier(&id, self.config.insecure_dev_mode).map_err(
            |_| {
                SigError::new(
                    SigErrorCode::InvalidKey,
                    "revocation signer id is not a server identifier",
                )
            },
        )?;

        // The body binds through the covered digest; verify the digest
        // against the received bytes before trusting anything in it.
        let digest = header("content-digest")
            .ok_or_else(|| SigError::new(SigErrorCode::InvalidInput, "missing Content-Digest"))?;
        sig::verify_content_digest(&digest, body)?;
        let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
            SigError::new(
                SigErrorCode::InvalidRequest,
                format!("revocation body: {e}"),
            )
        })?;
        let iss = json
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigError::new(SigErrorCode::InvalidRequest, "iss is required"))?
            .to_owned();
        let jti = json
            .get("jti")
            .and_then(|v| v.as_str())
            .filter(|j| !j.is_empty() && j.len() <= 512)
            .ok_or_else(|| SigError::new(SigErrorCode::InvalidRequest, "jti is required"))?
            .to_owned();
        // Only the issuer of a token may revoke it — and that is exactly what
        // scopes the deny-list entry the signer can create.
        if id != iss {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                "a revocation is accepted only from the issuer of the token being revoked",
            ));
        }
        Ok((parsed, id, dwk, kid, iss, jti))
    }

    async fn ps_key(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        if let Ok(cache) = self.ps_keys.lock()
            && let Some((jwks, at)) = cache.get(iss)
            && at.elapsed() < PS_KEYS_MAX_AGE
            && let Some(k) = jwks.find(kid)
        {
            return Ok(k);
        }
        self.ps_key_refresh(iss, dwk, kid).await
    }

    async fn ps_key_refresh(&self, iss: &str, dwk: &str, kid: &str) -> Result<Jwk, SigError> {
        {
            let mut attempts = self
                .ps_last_attempt
                .lock()
                .map_err(|_| SigError::new(SigErrorCode::UnknownKey, "key cache poisoned"))?;
            if let Some(last) = attempts.get(iss)
                && last.elapsed() < PS_KEYS_FLOOR
            {
                return Err(SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("kid '{kid}' not found for {iss} (fetch floor active)"),
                ));
            }
            if attempts.len() >= MAX_ENTRIES {
                attempts.clear();
            }
            attempts.insert(iss.to_owned(), Instant::now());
        }
        let insecure = self.config.insecure_dev_mode;
        let meta = fetch_json(&format!("{iss}/.well-known/{dwk}"), insecure)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("metadata fetch: {e}")))?;
        match meta.get("issuer").and_then(|v| v.as_str()) {
            None => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMissing,
                    "metadata document has no issuer",
                ));
            }
            Some(d) if d != iss => {
                return Err(SigError::new(
                    SigErrorCode::IssuerMismatch,
                    "metadata issuer does not match the signer id",
                ));
            }
            Some(_) => {}
        }
        let jwks_uri = meta
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SigError::new(SigErrorCode::UnknownKey, "metadata has no jwks_uri"))?;
        if aauth::ident::host_of(jwks_uri) != aauth::ident::host_of(iss) {
            return Err(SigError::new(
                SigErrorCode::InvalidKey,
                "jwks_uri host differs from the signer host",
            ));
        }
        let jwks_val = fetch_json(jwks_uri, insecure)
            .await
            .map_err(|e| SigError::new(SigErrorCode::UnknownKey, format!("jwks fetch: {e}")))?;
        let jwks: Jwks = serde_json::from_value(jwks_val)
            .map_err(|e| SigError::new(SigErrorCode::InvalidKey, format!("invalid JWKS: {e}")))?;
        let found = jwks.find(kid);
        let present = jwks.kid_present(kid);
        if let Ok(mut cache) = self.ps_keys.lock() {
            if cache.len() >= MAX_ENTRIES {
                cache.clear();
            }
            cache.insert(iss.to_owned(), (jwks, Instant::now()));
        }
        found.ok_or_else(|| {
            if present {
                SigError::new(
                    SigErrorCode::UnsupportedAlgorithm,
                    format!("kid '{kid}' at {iss} is a key type this build does not implement"),
                )
            } else {
                SigError::new(
                    SigErrorCode::UnknownKey,
                    format!("kid '{kid}' not in JWKS of {iss}"),
                )
            }
        })
    }
}

/// Load the resource signing key from config: a raw 32-byte seed file (raw
/// bytes or base64url text), an inline base64url seed, or a fresh ephemeral
/// key. The `kid` is the RFC 7638 thumbprint of the public key.
fn load_signing_key(cfg: &AauthSigningKeyConfig) -> Result<(SigningKey, String)> {
    let seed: [u8; 32] = if let Some(path) = &cfg.seed_file {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading aauth signing seed file {}", path.display()))?;
        if bytes.len() == 32 {
            bytes.as_slice().try_into().expect("checked length")
        } else {
            let text = String::from_utf8_lossy(&bytes);
            aauth::b64::decode_fixed(text.trim()).map_err(|e| {
                anyhow::anyhow!(
                    "aauth signing seed file {} is neither 32 raw bytes nor a base64url 32-byte \
                     seed: {e}",
                    path.display()
                )
            })?
        }
    } else if let Some(seed) = &cfg.seed {
        aauth::b64::decode_fixed(seed.trim()).map_err(|e| {
            anyhow::anyhow!("aauth signing seed is not a base64url 32-byte seed: {e}")
        })?
    } else if cfg.ephemeral {
        tracing::warn!(
            "server.aauth_resource_metadata.signing_key.ephemeral is set: the resource signing \
             key is regenerated on every start (development only — resource tokens minted before \
             a restart cannot be verified after it)"
        );
        let mut seed = [0u8; 32];
        aauth::rand_bytes(&mut seed);
        seed
    } else {
        anyhow::bail!(
            "server.aauth_resource_metadata.signing_key needs one of seed_file, seed, or \
             ephemeral: true"
        );
    };
    let key = SigningKey::from_bytes(&seed);
    let kid = Jwk::from_verifying_key(&key.verifying_key())
        .thumbprint()
        .expect("OKP thumbprint");
    Ok((key, kid))
}

/// Egress-admitted `GET` returning JSON: HTTPS only (unless dev), the host
/// resolved up front and refused when any address is private, the
/// connection pinned to the vetted address, no redirects, body and time
/// capped.
async fn fetch_json(url: &str, insecure: bool) -> Result<serde_json::Value, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("bad URL: {e}"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if insecure => {}
        other => return Err(format!("scheme '{other}' not admitted")),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("userinfo in URL rejected".into());
    }
    let host = parsed.host_str().ok_or("URL has no host")?.to_owned();
    let port = parsed.port_or_known_default().ok_or("URL has no port")?;
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("dns resolution of {host} failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host} did not resolve"));
    }
    if !insecure
        && addrs
            .iter()
            .any(|a| crate::runtime::safe_dns::is_private_address(&a.ip()))
    {
        return Err(format!("host {host} resolves to a non-public address"));
    }
    let pinned = addrs[0];
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(FETCH_TIMEOUT)
        .https_only(!insecure)
        .resolve(&host, pinned)
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;
    let resp = client
        .get(parsed)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.status().is_redirection() {
        return Err(format!("redirect from {url} refused"));
    }
    if !resp.status().is_success() {
        return Err(format!("HTTP {} from {url}", resp.status().as_u16()));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("read body failed: {e}"))?;
    if bytes.len() > FETCH_MAX_BYTES {
        return Err(format!(
            "response from {url} exceeds {FETCH_MAX_BYTES} bytes"
        ));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid JSON from {url}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg(access_mode: &str, key: Option<AauthSigningKeyConfig>) -> AauthResourceMetadataConfig {
        let mut scope_descriptions = BTreeMap::new();
        scope_descriptions.insert("tools:read".to_owned(), "Read tools".to_owned());
        scope_descriptions.insert("tools:write".to_owned(), "Write tools".to_owned());
        AauthResourceMetadataConfig {
            issuer: "https://gw.example".into(),
            access_mode: access_mode.into(),
            accept_signature_algs: vec!["Ed25519".into()],
            scope_descriptions,
            signing_key: key,
            ..Default::default()
        }
    }

    fn person_identity(with_mission: bool) -> RequestIdentity {
        let mut attributes = BTreeMap::new();
        attributes.insert(ATTR_TOKEN_TYPE.to_owned(), "person".to_owned());
        attributes.insert(ATTR_JTI.to_owned(), "pt-1".to_owned());
        attributes.insert(ATTR_PS.to_owned(), "https://ps.example".to_owned());
        attributes.insert(
            ATTR_AGENT_JKT.to_owned(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k".to_owned(),
        );
        attributes.insert(ATTR_EXP.to_owned(), (aauth::now_unix() + 600).to_string());
        if with_mission {
            attributes.insert(
                ATTR_MISSION.to_owned(),
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned(),
            );
        }
        RequestIdentity::Verified {
            subject_id: "8f14e45fceea167a5a36dedd4bea2543".into(),
            issuer: "https://ps.example".into(),
            auth_provider: "aauth".into(),
            source: "identity_plugin:verified".into(),
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes,
        }
    }

    #[test]
    fn auth_token_mode_requires_signing_key() {
        assert!(AauthResource::from_config(&cfg("auth-token", None)).is_err());
        assert!(AauthResource::from_config(&cfg("agent-token", None)).is_ok());
    }

    #[test]
    fn ephemeral_key_publishes_jwks_and_endpoints() {
        let r = AauthResource::from_config(&cfg(
            "auth-token",
            Some(AauthSigningKeyConfig {
                ephemeral: true,
                ..Default::default()
            }),
        ))
        .unwrap();
        let jwks = r.jwks_document();
        assert_eq!(jwks["keys"][0]["alg"], "Ed25519");
        assert_eq!(jwks["keys"][0]["kty"], "OKP");
        assert!(jwks["keys"][0]["kid"].is_string());
        let meta = r.metadata_document();
        assert_eq!(
            meta["jwks_uri"],
            "https://gw.example/.well-known/aauth-jwks.json"
        );
        assert_eq!(
            meta["authorization_endpoint"],
            "https://gw.example/aauth/authorize"
        );
        assert_eq!(
            meta["revocation_endpoint"],
            "https://gw.example/aauth/revoke"
        );
        assert_eq!(meta["scope_descriptions"]["tools:read"], "Read tools");
    }

    #[test]
    fn identity_only_mode_publishes_no_signing_surface() {
        let r = AauthResource::from_config(&cfg("agent-token", None)).unwrap();
        let meta = r.metadata_document();
        assert!(meta.get("jwks_uri").is_none());
        assert!(meta.get("authorization_endpoint").is_none());
        // Revocation is honoured in every mode.
        assert_eq!(
            meta["revocation_endpoint"],
            "https://gw.example/aauth/revoke"
        );
    }

    #[test]
    fn mints_resource_token_for_person_identity() {
        let r = AauthResource::from_config(&cfg(
            "auth-token",
            Some(AauthSigningKeyConfig {
                ephemeral: true,
                ..Default::default()
            }),
        ))
        .unwrap();
        let token = r
            .mint_resource_token(&person_identity(true), &["tools:read".to_owned()], None)
            .unwrap();
        let decoded = aauth::jwt::decode(&token).unwrap();
        // Verifies under the published key.
        let jwk: Jwk = serde_json::from_value(r.jwks_document()["keys"][0].clone()).unwrap();
        aauth::jwt::verify_with_jwk(&decoded, &jwk).unwrap();
        assert_eq!(decoded.header.typ.as_deref(), Some("aa-resource+jwt"));
        assert_eq!(decoded.payload["iss"], "https://gw.example");
        assert_eq!(decoded.payload["aud"], "https://ps.example");
        assert_eq!(decoded.payload["ps"], "https://ps.example");
        assert_eq!(decoded.payload["sub"], "8f14e45fceea167a5a36dedd4bea2543");
        assert_eq!(decoded.payload["presented_jti"], "pt-1");
        assert_eq!(
            decoded.payload["agent_jkt"],
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(decoded.payload["scope"], "tools:read");
        assert_eq!(
            decoded.payload["mission_s256"],
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert_eq!(decoded.payload["dwk"], "aauth-resource.json");
    }

    #[test]
    fn mint_refusals() {
        let r = AauthResource::from_config(&cfg(
            "auth-token",
            Some(AauthSigningKeyConfig {
                ephemeral: true,
                ..Default::default()
            }),
        ))
        .unwrap();
        // Unknown scope.
        assert_eq!(
            r.mint_resource_token(&person_identity(false), &["nope".to_owned()], None),
            Err(MintRefusal::UnknownScope("nope".into()))
        );
        // Anonymous / non-AAuth caller.
        let anon = RequestIdentity::Anonymous {
            source: "test".into(),
        };
        assert_eq!(
            r.mint_resource_token(&anon, &["tools:read".to_owned()], None),
            Err(MintRefusal::PersonTokenRequired)
        );
        // Identity-only deployment cannot mint.
        let r2 = AauthResource::from_config(&cfg("agent-token", None)).unwrap();
        assert_eq!(
            r2.mint_resource_token(&person_identity(false), &["tools:read".to_owned()], None),
            Err(MintRefusal::NoSigningKey)
        );
    }

    /// An auth-token identity can step up only when this replica remembers
    /// the person token that produced it.
    #[test]
    fn step_up_from_auth_token_needs_remembered_person_token() {
        let r = AauthResource::from_config(&cfg(
            "auth-token",
            Some(AauthSigningKeyConfig {
                ephemeral: true,
                ..Default::default()
            }),
        ))
        .unwrap();
        let mut auth = person_identity(true);
        if let RequestIdentity::Verified {
            attributes, scopes, ..
        } = &mut auth
        {
            attributes.insert(ATTR_TOKEN_TYPE.to_owned(), "auth".to_owned());
            attributes.insert(ATTR_JTI.to_owned(), "at-1".to_owned());
            scopes.push("tools:read".to_owned());
        }
        assert_eq!(
            r.mint_resource_token(&auth, &["tools:write".to_owned()], None),
            Err(MintRefusal::PersonTokenRequired)
        );
        // Once the person token was seen, the step-up names it.
        r.record_identity(&person_identity(true));
        let token = r
            .mint_resource_token(&auth, &["tools:write".to_owned()], None)
            .unwrap();
        let decoded = aauth::jwt::decode(&token).unwrap();
        assert_eq!(decoded.payload["presented_jti"], "pt-1");
        assert_eq!(
            decoded.payload["mission_s256"],
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
    }

    #[test]
    fn revocation_set_keys_by_issuer_and_jti() {
        let r = AauthResource::from_config(&cfg("agent-token", None)).unwrap();
        let id = person_identity(false);
        assert!(!r.is_revoked(&id));
        r.revoke("https://ps.example", "pt-1", aauth::now_unix() + 60);
        assert!(r.is_revoked(&id));
        // Same jti under a different issuer is a different token.
        r.revoke("https://other.example", "pt-1", aauth::now_unix() + 60);
        let mut other = person_identity(false);
        if let RequestIdentity::Verified { issuer, .. } = &mut other {
            *issuer = "https://third.example".into();
        }
        assert!(!r.is_revoked(&other));
        // Expired entries stop matching.
        r.revoke(
            "https://ps.example",
            "pt-2",
            aauth::now_unix().saturating_sub(1),
        );
        let mut old = person_identity(false);
        if let RequestIdentity::Verified { attributes, .. } = &mut old {
            attributes.insert(ATTR_JTI.to_owned(), "pt-2".to_owned());
        }
        assert!(!r.is_revoked(&old));
    }

    #[test]
    fn seed_loading_forms() {
        let seed = [9u8; 32];
        let b64 = aauth::b64::encode(&seed);
        let (k1, kid1) = load_signing_key(&AauthSigningKeyConfig {
            seed: Some(b64.clone()),
            ..Default::default()
        })
        .unwrap();
        let dir = std::env::temp_dir().join(format!("aauth-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("raw");
        std::fs::write(&raw, seed).unwrap();
        let text = dir.join("text");
        std::fs::write(&text, format!("{b64}\n")).unwrap();
        let (k2, kid2) = load_signing_key(&AauthSigningKeyConfig {
            seed_file: Some(raw),
            ..Default::default()
        })
        .unwrap();
        let (k3, kid3) = load_signing_key(&AauthSigningKeyConfig {
            seed_file: Some(text),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        assert_eq!(k2.to_bytes(), k3.to_bytes());
        assert_eq!(kid1, kid2);
        assert_eq!(kid2, kid3);
        assert!(load_signing_key(&AauthSigningKeyConfig::default()).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
