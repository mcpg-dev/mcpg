//! `oauth_impersonation` federations that present the caller's stored
//! enterprise IdP sign-in (`subject_token: idp_refresh_token` or
//! `idp_id_token`) instead of the caller's bearer.

use std::sync::{Arc, Mutex};

use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::credential_cache_clustered::CredentialCacheKind;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use serde_json::Value;

use super::tests::{
    SSO_ISSUER, empty_policy, fed_config, seen_for, spawn_auth_gated_mock, sso_principal,
    stub_manifest, untouchable_upstream,
};
use super::*;
use crate::backends::CapabilityRegistry;
use crate::runtime::authorization_server::connect::{ConnectLink, LinkError, LinkOffer};
use crate::runtime::authorization_server::grants::GrantEvent;
use crate::runtime::authorization_server::state::{GrantId, RevocationReason, SecretString};
use crate::runtime::authorization_server::vault::{
    IdpSessionEnd, IdpSubjectToken, SubjectTokenKind, VaultSubjectToken,
};

const LOGIN_ISSUER: &str = "https://acme.okta.com";
const LOGIN_TOKEN_ENDPOINT: &str = "https://acme.okta.com/oauth2/v1/token";
const LOGIN_CLIENT: &str = "0oa-gateway-login";
const CONNECT: &str = "https://mcp.acme.example/oauth/connect";
const BINDING: &str = "vault:principal-handle:0oa-gateway-login";

/// What the stored sign-in of every principal is.
#[derive(Clone)]
enum Stored {
    Token(&'static str),
    Missing,
    Ended,
    Unusable,
    Unavailable,
    NoLogin,
}

/// A link the vault was asked for: principal, client, session, whether the
/// session is told, and the link it resumes.
type LinkAsked = (String, Option<String>, Option<String>, bool, Option<String>);

/// The IdP sign-ins of an authorization server, answering every
/// principal alike and recording what it was asked.
struct FakeVault {
    stored: Mutex<Stored>,
    asked: Mutex<Vec<(String, SubjectTokenKind)>>,
    connect: Option<String>,
    links: Mutex<Vec<LinkAsked>>,
    /// Why no link is offered; `None` offers one.
    link_refusal: Mutex<Option<LinkError>>,
}

impl FakeVault {
    fn new(stored: Stored) -> Arc<Self> {
        Arc::new(Self::with_connect(stored, Some(CONNECT.to_owned())))
    }

    fn with_connect(stored: Stored, connect: Option<String>) -> Self {
        Self {
            stored: Mutex::new(stored),
            asked: Mutex::default(),
            connect,
            links: Mutex::default(),
            link_refusal: Mutex::default(),
        }
    }

    fn links(&self) -> Vec<LinkAsked> {
        self.links.lock().expect("links lock").clone()
    }

    fn store(&self, stored: Stored) {
        *self.stored.lock().expect("stored lock") = stored;
    }

    fn asked(&self) -> Vec<(String, SubjectTokenKind)> {
        self.asked.lock().expect("asked lock").clone()
    }
}

#[async_trait::async_trait]
impl IdpSessionSource for FakeVault {
    async fn subject_token(&self, principal: &str, kind: SubjectTokenKind) -> IdpSubjectToken {
        self.asked
            .lock()
            .expect("asked lock")
            .push((principal.to_owned(), kind));
        let stored = self.stored.lock().expect("stored lock").clone();
        match stored {
            Stored::Token(token) => IdpSubjectToken::Linked(VaultSubjectToken {
                token: SecretString::new(token),
                kind,
                issuer: LOGIN_ISSUER.to_owned(),
                token_endpoint: LOGIN_TOKEN_ENDPOINT.to_owned(),
                client_id: LOGIN_CLIENT.to_owned(),
                binding: format!("{BINDING}:{}", kind.as_str()),
            }),
            Stored::Missing => IdpSubjectToken::NotLinked {
                reason: "no usable enterprise sign-in is stored for this user",
                events: Vec::new(),
            },
            Stored::Ended => IdpSubjectToken::NotLinked {
                reason: "the enterprise IdP ended the stored sign-in",
                events: vec![
                    GrantEvent::Revoked {
                        gid: GrantId::parse("0123456789abcdef0123456789abcdef").expect("grant id"),
                        reason: RevocationReason::IdpRefused,
                        client_id: Some("web-app".to_owned()),
                    },
                    GrantEvent::IdpSessionRemoved {
                        idp: LOGIN_ISSUER.to_owned(),
                        subject: "00u-alice".to_owned(),
                        reason: IdpSessionEnd::IdpRefused,
                    },
                ],
            },
            Stored::Unusable => IdpSubjectToken::Unusable {
                reason: "the enterprise IdP issued no refresh token at sign-in; add \
                         offline_access to trusted_idps[].login.scopes",
            },
            Stored::Unavailable => IdpSubjectToken::Unavailable {
                reason: "the sign-in state store is unavailable".to_owned(),
            },
            Stored::NoLogin => IdpSubjectToken::NoLogin,
        }
    }

    fn connect_url(&self) -> Option<String> {
        self.connect.clone()
    }

    fn login_issuer(&self) -> Option<String> {
        Some(LOGIN_ISSUER.to_owned())
    }

    /// The login IdP's own namespace, and the SSO provider its
    /// `principal_issuer` joins.
    fn stores_sign_in_for(&self, auth_provider: &str, issuer: &str) -> bool {
        (auth_provider == "ema" && issuer == LOGIN_ISSUER)
            || (auth_provider == format!("oidc_oauth:{SSO_ISSUER}") && issuer == SSO_ISSUER)
    }

    async fn offer_link(&self, offer: LinkOffer<'_>) -> Result<ConnectLink, LinkError> {
        let mut links = self.links.lock().expect("links lock");
        links.push((
            offer.principal.to_owned(),
            offer.client_id.map(str::to_owned),
            offer.session_id.map(str::to_owned),
            offer.notify,
            offer.resume.map(str::to_owned),
        ));
        if let Some(refusal) = self.link_refusal.lock().expect("refusal lock").clone() {
            return Err(refusal);
        }
        let id = offer
            .resume
            .map_or_else(|| format!("link-{}", links.len()), str::to_owned);
        Ok(ConnectLink {
            url: format!("{CONNECT}?e={id}"),
            resumed: offer.resume.is_some(),
            id,
            expires_at: 1_900_000_000,
            idp_name: "Acme SSO".to_owned(),
        })
    }
}

type Issued = Arc<Mutex<Vec<PluginIdentity>>>;
type Audited = Arc<tokio::sync::Mutex<Vec<AuditEvent>>>;
type Refusal = Arc<Mutex<Option<mcpg_plugin_protocol::credential::CredentialError>>>;

/// The manifest id of the token-exchange issuer the federations name: one
/// that may be handed a stored sign-in.
const EXCHANGE: &str = "dev.mcpg.credential.oauth-token-exchange";

/// A token-exchange issuer that mints `exchanged-<subject token>`, with
/// `+<scope>` for each scope of the caller, or fails with `refusal` when
/// one is set, and records the identity of each issuance.
struct RecordingExchange {
    manifest: mcpg_plugin_protocol::manifest::PluginManifest,
    issued: Issued,
    refusal: Refusal,
}

#[async_trait::async_trait]
impl mcpg_plugin_protocol::credential::CredentialIssuer for RecordingExchange {
    fn manifest(&self) -> &mcpg_plugin_protocol::manifest::PluginManifest {
        &self.manifest
    }

    async fn issue(
        &self,
        identity: &PluginIdentity,
        _target: &str,
        _config: &Value,
    ) -> Result<
        mcpg_plugin_protocol::credential::IssuedCredential,
        mcpg_plugin_protocol::credential::CredentialError,
    > {
        self.issued
            .lock()
            .expect("issued lock")
            .push(identity.clone());
        if let Some(refusal) = self.refusal.lock().expect("refusal lock").clone() {
            return Err(refusal);
        }
        let subject = identity
            .attributes
            .get("subject_token")
            .cloned()
            .unwrap_or_default();
        let scopes: String = identity
            .scopes
            .iter()
            .map(|scope| format!("+{scope}"))
            .collect();
        Ok(
            mcpg_plugin_protocol::credential::IssuedCredential::from_value(
                format!("exchanged-{subject}{scopes}"),
                600,
            ),
        )
    }
}

/// An audit sink that keeps every event.
struct RecordingAudit {
    manifest: mcpg_plugin_protocol::manifest::PluginManifest,
    audited: Audited,
}

#[async_trait::async_trait]
impl mcpg_plugin_protocol::audit::AuditSink for RecordingAudit {
    fn manifest(&self) -> &mcpg_plugin_protocol::manifest::PluginManifest {
        &self.manifest
    }

    async fn emit(
        &self,
        event: &AuditEvent,
    ) -> Result<mcpg_plugin_protocol::audit::AuditReceipt, mcpg_plugin_protocol::audit::AuditError>
    {
        self.audited.lock().await.push(event.clone());
        Ok(mcpg_plugin_protocol::audit::AuditReceipt {
            sink_id: self.manifest.id.clone(),
            persisted_at: "2026-09-28T00:00:00Z".to_owned(),
            durable_hash: "0".repeat(64),
        })
    }
}

/// The recording exchange as [`EXCHANGE`], the same issuer as
/// `stub.exchange`, which may not be handed a stored sign-in, and a
/// recording audit sink behind a local credential cache.
fn credentials() -> (
    Arc<PluginRegistry>,
    Arc<CredentialCacheKind>,
    Issued,
    Audited,
    Refusal,
) {
    let issued = Issued::default();
    let audited = Audited::default();
    let refusal = Refusal::default();
    let mut registry = PluginRegistry::new();
    for id in [EXCHANGE, "stub.exchange"] {
        registry
            .register_credential_issuer(
                Arc::new(RecordingExchange {
                    manifest: stub_manifest(id),
                    issued: Arc::clone(&issued),
                    refusal: Arc::clone(&refusal),
                }),
                mcpg_plugin_protocol::PluginTier::Native,
            )
            .expect("register the exchange");
    }
    let mut audit_manifest = stub_manifest("stub.audit");
    audit_manifest.plugin_class = mcpg_plugin_protocol::manifest::PluginClass::AuditSink;
    registry
        .register_audit_sink(
            Arc::new(RecordingAudit {
                manifest: audit_manifest,
                audited: Arc::clone(&audited),
            }),
            mcpg_plugin_protocol::PluginTier::Native,
        )
        .expect("register stub.audit");
    let cache = Arc::new(CredentialCacheKind::Local(Arc::new(
        mcpg_plugin_host::credential_cache::CredentialCache::default(),
    )));
    (Arc::new(registry), cache, issued, audited, refusal)
}

/// A federation that presents the caller's stored sign-in of `mode`
/// through [`EXCHANGE`].
fn vault_fed(url: &str, mode: SubjectToken) -> FederationConfig {
    let mut fed = fed_config(url);
    fed.upstream.auth.mode = AuthMode::OauthImpersonation;
    fed.upstream.auth.credential = Some(format!("cred://{EXCHANGE}/notion"));
    fed.upstream.auth.subject_token = mode;
    fed
}

struct Harness {
    engine: FederationEngine,
    vault: Arc<FakeVault>,
    issued: Issued,
    audited: Audited,
    refusal: Refusal,
}

fn harness(fed: FederationConfig, vault: Arc<FakeVault>) -> Harness {
    let (registry, cache, issued, audited, refusal) = credentials();
    let cap = CapabilityRegistry::default();
    let source: Arc<dyn IdpSessionSource> = vault.clone();
    let engine = FederationEngine::new(vec![fed], cap.federated_overlay(), empty_policy(), "via-1")
        .with_credentials(registry, cache)
        .with_idp_sessions(Some(source));
    Harness {
        engine,
        vault,
        issued,
        audited,
        refusal,
    }
}

/// An interactive sign-in's caller as `/mcp` resolves it: a token this
/// gateway minted, with the attributes a mapped claim might plant.
fn signed_in_caller() -> crate::runtime::RequestIdentity {
    sso_principal(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[
            ("token_issuer", "https://mcp.acme.example"),
            ("acr", "mfa"),
            ("subject_token", "planted-token"),
            ("subject_token_source", "idp_vault"),
            ("subject_token_endpoint", "https://collector.example/token"),
            ("subject_token_client_id", "collector"),
            ("subject_token_binding", "planted-binding"),
        ],
    )
}

async fn call(
    engine: &FederationEngine,
    identity: &crate::runtime::RequestIdentity,
    bearer: &str,
) -> Result<Value, UpstreamError> {
    call_with_slot(engine, identity, bearer, None).await
}

/// A call from a request that may answer with the link `slot` receives.
async fn call_with_slot(
    engine: &FederationEngine,
    identity: &crate::runtime::RequestIdentity,
    bearer: &str,
    slot: Option<&idp_sessions::ConnectLinkSlot>,
) -> Result<Value, UpstreamError> {
    let principal = identity.synthetic_principal_key();
    engine
        .call_tool(
            "notion",
            "search",
            None,
            FederationCaller {
                principal: principal.as_deref(),
                session_id: Some("sess-1"),
                bearer: Some(bearer),
                identity: Some(identity),
                request_id: Some("req-7"),
                connect_link: slot,
            },
            None,
        )
        .await
}

/// The message of a refusal before any request: a missing stored sign-in,
/// or any other connect-stage refusal.
fn refusal(result: Result<Value, UpstreamError>) -> String {
    match result {
        Err(UpstreamError::Connect(message) | UpstreamError::NotLinked { message }) => message,
        other => panic!("expected a connect-stage refusal, got {other:?}"),
    }
}

async fn audited(audited: &Audited) -> Vec<AuditEvent> {
    audited.lock().await.clone()
}

async fn upstream_calls(upstream: &wiremock::MockServer) -> usize {
    upstream
        .received_requests()
        .await
        .expect("request recording")
        .len()
}

#[tokio::test]
async fn a_stored_refresh_token_is_exchanged_for_a_gateway_minted_caller() {
    let (url, seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let caller = signed_in_caller();
    let result = call(&h.engine, &caller, "gw-minted-at")
        .await
        .expect("call_tool");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("auth=Bearer exchanged-idp-rt-1"),
        "{result:?}"
    );
    assert_eq!(
        seen_for(&seen, "tools/call"),
        vec!["Bearer exchanged-idp-rt-1".to_owned()]
    );
    assert_eq!(
        h.vault.asked(),
        vec![(
            caller.synthetic_principal_key().expect("principal"),
            SubjectTokenKind::RefreshToken
        )]
    );

    let issued = h.issued.lock().expect("issued lock").clone();
    assert_eq!(issued.len(), 1);
    let attributes = &issued[0].attributes;
    for (name, value) in [
        ("subject_token", "idp-rt-1"),
        (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:refresh_token",
        ),
        ("subject_token_source", "idp_vault"),
        ("subject_token_issuer", LOGIN_ISSUER),
        ("subject_token_endpoint", LOGIN_TOKEN_ENDPOINT),
        ("subject_token_client_id", LOGIN_CLIENT),
        ("subject_token_binding", &format!("{BINDING}:refresh_token")),
        ("token_issuer", "https://mcp.acme.example"),
        ("acr", "mfa"),
    ] {
        assert_eq!(
            attributes.get(name).map(String::as_str),
            Some(value),
            "{name}"
        );
    }
    assert!(
        !attributes
            .values()
            .any(|value| value.contains("gw-minted-at")),
        "the caller's bearer reached the issuer: {attributes:?}"
    );
    assert_eq!(issued[0].subject_id.as_deref(), Some("user-42"));
    assert!(audited(&h.audited).await.is_empty());
}

#[tokio::test]
async fn an_id_token_federation_presents_the_stored_id_token() {
    let (url, seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpIdToken),
        FakeVault::new(Stored::Token("idp-id-token")),
    );
    call(&h.engine, &signed_in_caller(), "gw-minted-at")
        .await
        .expect("call_tool");
    assert_eq!(h.vault.asked()[0].1, SubjectTokenKind::IdToken);
    let issued = h.issued.lock().expect("issued lock").clone();
    assert_eq!(
        issued[0].attributes["subject_token_type"],
        "urn:ietf:params:oauth:token-type:id_token"
    );
    assert_eq!(
        issued[0].attributes["subject_token_binding"],
        format!("{BINDING}:id_token")
    );
    assert_eq!(
        seen_for(&seen, "tools/call"),
        vec!["Bearer exchanged-idp-id-token".to_owned()]
    );
}

/// An SSO caller the IdP's `principal_issuer` joins to the signed-in user
/// presents the same stored sign-in: the principal decides, not how the
/// caller authenticated.
#[tokio::test]
async fn an_sso_caller_presents_the_stored_sign_in_of_their_principal() {
    let (url, seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let sso = sso_principal("authorization:oidc_oauth", &[]);
    call(&h.engine, &sso, "okta-at").await.expect("call_tool");
    assert_eq!(
        h.vault.asked()[0].0,
        format!("verified::oidc_oauth:{SSO_ISSUER}::{SSO_ISSUER}::user-42")
    );
    assert_eq!(
        seen_for(&seen, "tools/call"),
        vec!["Bearer exchanged-idp-rt-1".to_owned()]
    );
}

#[tokio::test]
async fn a_caller_with_no_stored_sign_in_is_sent_to_the_connect_page_before_any_request() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Missing),
    );
    let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(
        message.contains("no enterprise sign-in is stored for you")
            && message.contains(&format!("open {CONNECT} once, then retry")),
        "{message}"
    );
    assert!(!message.contains("gw-minted-at"), "{message}");
    assert!(h.issued.lock().expect("issued lock").is_empty());
    assert_eq!(upstream_calls(&upstream).await, 0);

    let events = audited(&h.audited).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.action, "mcpg.federation.idp_subject_token");
    assert_eq!(event.outcome, AuditOutcome::Denied);
    assert_eq!(event.request_id.as_deref(), Some("req-7"));
    assert_eq!(event.resource.as_deref(), Some("federation://notion"));
    assert_eq!(event.details["outcome"], "not_linked");
    assert_eq!(event.details["mode"], "idp_refresh_token");
    assert_eq!(event.actor.subject_id.as_deref(), Some("user-42"));
    let serialized = serde_json::to_string(event).expect("event serializes");
    assert!(!serialized.contains("gw-minted-at"), "{serialized}");
}

/// A request that may answer with a URL elicitation offers the caller a
/// link bound to their principal, client and session, and still sends
/// nothing upstream; the refusal is the typed missing sign-in.
#[tokio::test]
async fn a_request_that_may_elicit_offers_a_link_bound_to_the_caller() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Missing),
    );
    let caller = sso_principal(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[
            ("token_issuer", "https://mcp.acme.example"),
            ("idp", LOGIN_ISSUER),
            ("client_id", "claude-desktop"),
        ],
    );
    let slot = idp_sessions::ConnectLinkSlot::default();
    assert!(slot.open(Some("sess-1".to_owned())));
    let result = call_with_slot(&h.engine, &caller, "gw-minted-at", Some(&slot)).await;
    let Err(UpstreamError::NotLinked { message }) = result else {
        panic!("expected the typed missing sign-in, got {result:?}");
    };
    assert!(message.contains(CONNECT), "{message}");

    let elicitation = slot.take_offered().expect("a link is offered");
    assert_eq!(elicitation.url, format!("{CONNECT}?e=link-1"));
    assert_eq!(elicitation.id, "link-1");
    assert!(
        elicitation.message.contains("`notion`") && elicitation.message.contains("Acme SSO"),
        "{}",
        elicitation.message
    );
    assert!(!elicitation.message.contains("user-42"));
    assert!(slot.take_offered().is_none(), "the slot closes once taken");
    assert_eq!(
        h.vault.links(),
        vec![(
            caller.synthetic_principal_key().expect("principal"),
            Some("claude-desktop".to_owned()),
            Some("sess-1".to_owned()),
            true,
            None,
        )]
    );
    assert_eq!(upstream_calls(&upstream).await, 0);
    let events = audited(&h.audited).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].details["outcome"], "not_linked");
}

/// The retry of a request that offered a link offers the same one again,
/// without telling a session; a declined link is not offered again; a slot
/// nobody opened offers none.
#[tokio::test]
async fn a_retry_resumes_its_link_and_a_declined_or_closed_slot_offers_none() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Missing),
    );
    let caller = signed_in_caller();

    let resumed = idp_sessions::ConnectLinkSlot::default();
    resumed.resume("link-7".to_owned());
    assert!(resumed.open(None));
    let _ = call_with_slot(&h.engine, &caller, "gw-minted-at", Some(&resumed)).await;
    let elicitation = resumed.take_offered().expect("the link is offered again");
    assert_eq!(elicitation.id, "link-7");
    let (_, client_id, session_id, notify, resume) = h.vault.links()[0].clone();
    assert_eq!(client_id, None, "the caller's token names no client");
    assert_eq!(session_id.as_deref(), Some("sess-1"));
    assert!(!notify);
    assert_eq!(resume.as_deref(), Some("link-7"));

    let declined = idp_sessions::ConnectLinkSlot::default();
    declined.decline();
    assert!(!declined.open(Some("sess-1".to_owned())));
    let refused = call_with_slot(&h.engine, &caller, "gw-minted-at", Some(&declined)).await;
    assert!(matches!(refused, Err(UpstreamError::NotLinked { .. })));
    assert!(declined.take_offered().is_none());

    let closed = idp_sessions::ConnectLinkSlot::default();
    let _ = call_with_slot(&h.engine, &caller, "gw-minted-at", Some(&closed)).await;
    assert!(closed.take_offered().is_none());
    assert_eq!(
        h.vault.links().len(),
        1,
        "only the open slot asked for a link"
    );
    assert_eq!(upstream_calls(&upstream).await, 0);
}

/// A verified caller that reports `auth_provider` and `issuer`, from the
/// credential `source`.
fn caller_in(
    source: &str,
    auth_provider: &str,
    issuer: &str,
    attributes: &[(&str, &str)],
) -> crate::runtime::RequestIdentity {
    crate::runtime::RequestIdentity::Verified {
        subject_id: "user-42".to_owned(),
        issuer: issuer.to_owned(),
        auth_provider: auth_provider.to_owned(),
        source: source.to_owned(),
        roles: Vec::new(),
        groups: Vec::new(),
        scopes: Vec::new(),
        attributes: attributes
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// No link is offered to a caller whose IdP signs nobody in here, nor
/// when the vault cannot offer one; the refusal stays.
#[tokio::test]
async fn no_link_is_offered_that_could_not_be_completed() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Missing),
    );
    let partner = caller_in(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        "ema",
        "https://partner.example",
        &[("idp", "https://partner.example")],
    );
    let slot = idp_sessions::ConnectLinkSlot::default();
    slot.open(None);
    let message = refusal(call_with_slot(&h.engine, &partner, "gw-minted-at", Some(&slot)).await);
    assert!(message.contains("https://partner.example"), "{message}");
    assert!(slot.take_offered().is_none());
    assert!(h.vault.links().is_empty());

    *h.vault.link_refusal.lock().expect("refusal lock") =
        Some(LinkError::Unavailable("store down".to_owned()));
    let slot = idp_sessions::ConnectLinkSlot::default();
    slot.open(None);
    let refused = call_with_slot(&h.engine, &signed_in_caller(), "gw-minted-at", Some(&slot)).await;
    assert!(matches!(refused, Err(UpstreamError::NotLinked { .. })));
    assert!(slot.take_offered().is_none());
    assert_eq!(upstream_calls(&upstream).await, 0);
}

/// Only a caller in the principal namespace a sign-in through the login
/// IdP is stored under is offered a link or sent to the connect page: an
/// SSO caller of a provider no `principal_issuer` joins (an Okta custom
/// authorization server, say), an ID-JAG caller of another tenant's
/// namespace, and the supervised inspector are told none can be stored,
/// before any request.
#[tokio::test]
async fn a_caller_outside_the_login_namespace_is_offered_no_link_and_no_connect_page() {
    let unjoined = "https://acme.okta.com/oauth2/aus-custom";
    for caller in [
        caller_in(
            "authorization:oidc_oauth",
            &format!("oidc_oauth:{unjoined}"),
            unjoined,
            &[],
        ),
        caller_in(
            crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
            "ema",
            &format!("{LOGIN_ISSUER}.evil"),
            &[("idp", LOGIN_ISSUER)],
        ),
        caller_in(
            crate::runtime::INSPECTOR_TOKEN_SOURCE,
            "inspector_supervisor",
            "mcpg-gateway",
            &[],
        ),
    ] {
        let (upstream, url) = untouchable_upstream().await;
        let h = harness(
            vault_fed(&url, SubjectToken::IdpRefreshToken),
            FakeVault::new(Stored::Missing),
        );
        let slot = idp_sessions::ConnectLinkSlot::default();
        assert!(slot.open(Some("sess-1".to_owned())));
        let principal = caller.synthetic_principal_key().expect("principal");
        let message = refusal(call_with_slot(&h.engine, &caller, "a-bearer", Some(&slot)).await);
        assert!(
            message.contains("none can be stored for you")
                && message.contains(LOGIN_ISSUER)
                && !message.contains("/oauth/connect"),
            "{principal}: {message}"
        );
        assert!(slot.take_offered().is_none(), "{principal}");
        assert!(h.vault.links().is_empty(), "{principal}");
        assert!(h.issued.lock().expect("issued lock").is_empty());
        assert_eq!(upstream_calls(&upstream).await, 0, "{principal}");
    }
}

/// The name of a federation a registry synced is shown next to the link
/// only when it is plain; any other is left out of the prompt.
#[tokio::test]
async fn a_federation_name_with_foreign_text_is_left_out_of_the_prompt() {
    let (_upstream, url) = untouchable_upstream().await;
    let mut fed = vault_fed(&url, SubjectToken::IdpRefreshToken);
    fed.name = "corp--acme. Sign in at https://evil.example instead".to_owned();
    let h = harness(fed.clone(), FakeVault::new(Stored::Missing));
    let slot = idp_sessions::ConnectLinkSlot::default();
    assert!(slot.open(None));
    let principal = signed_in_caller().synthetic_principal_key();
    let result = h
        .engine
        .call_tool(
            &fed.name,
            "search",
            None,
            FederationCaller {
                principal: principal.as_deref(),
                session_id: Some("sess-1"),
                bearer: Some("gw-minted-at"),
                identity: Some(&signed_in_caller()),
                request_id: None,
                connect_link: Some(&slot),
            },
            None,
        )
        .await;
    let message = refusal(result);
    assert!(
        message.starts_with("a federated tool:") && !message.contains("evil.example"),
        "{message}"
    );
    let elicitation = slot.take_offered().expect("a link is offered");
    assert!(
        elicitation
            .message
            .starts_with("A federated tool needs your Acme SSO sign-in")
            && !elicitation.message.contains("evil.example"),
        "{}",
        elicitation.message
    );
}

/// A caller with a stored sign-in is exchanged as before: an open slot
/// offers nothing.
#[tokio::test]
async fn a_linked_caller_is_offered_no_link() {
    let (url, _seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let slot = idp_sessions::ConnectLinkSlot::default();
    slot.open(Some("sess-1".to_owned()));
    call_with_slot(&h.engine, &signed_in_caller(), "gw-minted-at", Some(&slot))
        .await
        .expect("call_tool");
    assert!(slot.take_offered().is_none());
    assert!(h.vault.links().is_empty());
}

#[tokio::test]
async fn without_the_connect_page_the_caller_is_told_to_sign_in_from_a_client() {
    let (upstream, url) = untouchable_upstream().await;
    let vault = Arc::new(FakeVault::with_connect(Stored::Missing, None));
    let h = harness(vault_fed(&url, SubjectToken::IdpRefreshToken), vault);
    let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(
        message.contains(&format!("sign in to this gateway through {LOGIN_ISSUER}"))
            && !message.contains("/oauth/connect"),
        "{message}"
    );
    assert_eq!(upstream_calls(&upstream).await, 0);
}

/// A caller whose ID-JAG came from an IdP the gateway does not sign users
/// in through can never store a sign-in; the error says so.
#[tokio::test]
async fn a_caller_of_an_idp_without_sign_in_is_told_none_can_be_stored() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Missing),
    );
    let caller = caller_in(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        "ema",
        "https://partner.example",
        &[
            ("token_issuer", "https://mcp.acme.example"),
            ("idp", "https://partner.example"),
        ],
    );
    let message = refusal(call(&h.engine, &caller, "gw-minted-at").await);
    assert!(
        message.contains("you signed in through https://partner.example")
            && message.contains("none can be stored for you")
            && message.contains(&format!("only users of {LOGIN_ISSUER} can store one"))
            && message.contains("principal_issuer")
            && !message.contains("/oauth/connect"),
        "{message}"
    );
    assert_eq!(upstream_calls(&upstream).await, 0);

    let own_idp = sso_principal(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[("idp", LOGIN_ISSUER)],
    );
    let message = refusal(call(&h.engine, &own_idp, "gw-minted-at").await);
    assert!(message.contains(CONNECT), "{message}");
}

/// The IdP ended the stored sign-in while it was read: the error says so,
/// and what that did to the user's grants is audited with the refusal.
#[tokio::test]
async fn a_sign_in_the_idp_ended_is_refused_and_its_end_audited() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpIdToken),
        FakeVault::new(Stored::Ended),
    );
    let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(
        message.contains("was ended by the IdP") && message.contains(CONNECT),
        "{message}"
    );
    assert_eq!(upstream_calls(&upstream).await, 0);
    let actions: Vec<String> = audited(&h.audited)
        .await
        .into_iter()
        .map(|event| {
            assert_eq!(event.request_id.as_deref(), Some("req-7"));
            event.action
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            "mcpg.as.grant_revoked",
            "mcpg.as.idp_session_removed",
            "mcpg.federation.idp_subject_token",
        ]
    );
}

#[tokio::test]
async fn an_unusable_or_unreadable_sign_in_is_refused_before_any_request() {
    for (stored, expected, outcome, audit_outcome) in [
        (
            Stored::Unusable,
            "add offline_access",
            "refused",
            AuditOutcome::Denied,
        ),
        (
            Stored::Unavailable,
            "retry shortly",
            "unavailable",
            AuditOutcome::Failure,
        ),
        (
            Stored::NoLogin,
            "no trusted IdP of the authorization server has a login block",
            "refused",
            AuditOutcome::Denied,
        ),
    ] {
        let (upstream, url) = untouchable_upstream().await;
        let h = harness(
            vault_fed(&url, SubjectToken::IdpRefreshToken),
            FakeVault::new(stored),
        );
        let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
        assert!(message.contains(expected), "{expected}: {message}");
        assert!(h.issued.lock().expect("issued lock").is_empty());
        assert_eq!(upstream_calls(&upstream).await, 0);
        let events = audited(&h.audited).await;
        assert_eq!(events.len(), 1, "{expected}");
        assert_eq!(events[0].details["outcome"], outcome, "{expected}");
        assert_eq!(events[0].outcome, audit_outcome, "{expected}");
    }
}

#[tokio::test]
async fn an_unverified_caller_is_refused_without_reading_any_sign_in() {
    let (upstream, url) = untouchable_upstream().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let header_asserted = crate::runtime::RequestIdentity::HttpHeader {
        subject_id: "alice".to_owned(),
        source: "x-user".to_owned(),
    };
    let message = refusal(call(&h.engine, &header_asserted, "some-bearer").await);
    assert!(message.contains("only a verified caller"), "{message}");
    assert!(h.vault.asked().is_empty());
    assert!(h.issued.lock().expect("issued lock").is_empty());
    assert_eq!(upstream_calls(&upstream).await, 0);
}

#[tokio::test]
async fn without_interactive_sign_in_the_federation_is_refused() {
    let (upstream, url) = untouchable_upstream().await;
    let (registry, cache, issued, _, _) = credentials();
    let cap = CapabilityRegistry::default();
    let engine = FederationEngine::new(
        vec![vault_fed(&url, SubjectToken::IdpRefreshToken)],
        cap.federated_overlay(),
        empty_policy(),
        "via-1",
    )
    .with_credentials(registry, cache);
    let message = refusal(call(&engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(
        message.contains("keeps none") && message.contains("trusted_idps[].login"),
        "{message}"
    );
    assert!(issued.lock().expect("issued lock").is_empty());
    assert_eq!(upstream_calls(&upstream).await, 0);
}

/// The catalogue sessions have no caller, so they read no sign-in and
/// connect anonymously, as `caller_bearer` does without a bearer.
#[tokio::test]
async fn catalogue_sessions_read_no_sign_in() {
    let fed = vault_fed("http://127.0.0.1:9/mcp", SubjectToken::IdpRefreshToken);
    let h = harness(fed.clone(), FakeVault::new(Stored::Token("idp-rt-1")));
    assert_eq!(h.engine.catalog_bearer(&fed).await.expect("bearer"), None);
    assert!(h.vault.asked().is_empty());
}

/// The upstream session is keyed by the principal and the kind of stored
/// token, so a caller whose gateway access token rotated keeps it; the
/// credential cache keys the vault token by its binding, so an IdP that
/// rotated the stored refresh token costs no second exchange.
#[tokio::test]
async fn rotations_keep_the_upstream_session_and_the_cached_credential() {
    let (url, seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let caller = signed_in_caller();
    call(&h.engine, &caller, "gw-minted-at-1")
        .await
        .expect("first call");
    h.vault.store(Stored::Token("idp-rt-2"));
    call(&h.engine, &caller, "gw-minted-at-2")
        .await
        .expect("second call");

    assert_eq!(
        h.issued.lock().expect("issued lock").len(),
        1,
        "the rotated stored token reused the cached credential"
    );
    assert_eq!(
        seen_for(&seen, "tools/call"),
        vec!["Bearer exchanged-idp-rt-1".to_owned(); 2]
    );
    assert_eq!(
        seen_for(&seen, "initialize").len(),
        1,
        "one upstream session across the caller's token rotation"
    );

    let fed = vault_fed(&url, SubjectToken::IdpRefreshToken);
    let principal = caller.synthetic_principal_key();
    let key = |bearer| {
        satellite_caller_key(
            &fed,
            &FederationCaller {
                principal: principal.as_deref(),
                session_id: Some("sess-1"),
                bearer: Some(bearer),
                identity: Some(&caller),
                request_id: None,
                connect_link: None,
            },
            &[],
        )
    };
    assert_eq!(key("gw-minted-at-1"), key("gw-minted-at-2"));
    assert!(
        key("gw-minted-at-1").contains("#vrefresh_token#i"),
        "{}",
        key("gw-minted-at-1")
    );
    let id_token_fed = vault_fed(&url, SubjectToken::IdpIdToken);
    assert_ne!(
        key("gw-minted-at-1"),
        satellite_caller_key(
            &id_token_fed,
            &FederationCaller {
                principal: principal.as_deref(),
                session_id: Some("sess-1"),
                bearer: Some("gw-minted-at-1"),
                identity: Some(&caller),
                request_id: None,
                connect_link: None,
            },
            &[],
        )
    );
}

/// The one user as a caller with `scopes`, through an MCP client whose
/// token names `client_id`.
fn client_of_user(scopes: &[&str], client_id: &str) -> crate::runtime::RequestIdentity {
    let mut identity = sso_principal(
        crate::runtime::EMA_ACCESS_TOKEN_SOURCE,
        &[("client_id", client_id), ("tenant", "acme")],
    );
    if let crate::runtime::RequestIdentity::Verified {
        scopes: ref mut held,
        ..
    } = identity
    {
        *held = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    }
    identity
}

/// Two MCP clients of one user whose tokens carry different scopes resolve
/// different upstream credentials, so each keeps its own upstream session:
/// alternating calls neither replace nor close the other's. What the
/// credential cache folds from `key_attributes` separates them too.
#[tokio::test]
async fn two_clients_of_one_user_with_different_scopes_keep_their_own_upstream_sessions() {
    let (url, seen) = spawn_auth_gated_mock().await;
    let h = harness(
        vault_fed(&url, SubjectToken::IdpRefreshToken),
        FakeVault::new(Stored::Token("idp-rt-1")),
    );
    let desktop = client_of_user(&["mcp:tools"], "claude-desktop");
    let ide = client_of_user(&["mcp:tools", "mcp:resources"], "vscode");
    for _ in 0..2 {
        call(&h.engine, &desktop, "gw-at-desktop")
            .await
            .expect("the desktop client's call");
        call(&h.engine, &ide, "gw-at-ide")
            .await
            .expect("the IDE's call");
    }
    assert_eq!(
        seen_for(&seen, "initialize").len(),
        2,
        "one upstream session per client, none replaced"
    );
    assert_eq!(seen_for(&seen, "tools/call").len(), 4);
    assert_eq!(
        h.issued.lock().expect("issued lock").len(),
        2,
        "one exchange per credential the cache keys"
    );

    let fed = vault_fed(&url, SubjectToken::IdpRefreshToken);
    let key = |identity: &crate::runtime::RequestIdentity, key_attributes: &[String]| {
        let principal = identity.synthetic_principal_key();
        satellite_caller_key(
            &fed,
            &FederationCaller {
                principal: principal.as_deref(),
                session_id: None,
                bearer: Some("gw-at"),
                identity: Some(identity),
                request_id: None,
                connect_link: None,
            },
            key_attributes,
        )
    };
    let same_scopes = client_of_user(&["mcp:tools"], "vscode");
    assert_eq!(
        key(&desktop, &[]),
        key(&same_scopes, &[]),
        "a client id the cache does not fold keeps one session"
    );
    let client_id = ["client_id".to_owned()];
    assert_ne!(
        key(&desktop, &client_id),
        key(&same_scopes, &client_id),
        "a folded attribute separates the sessions as it separates the credentials"
    );
    let mut planted = client_of_user(&["mcp:tools"], "claude-desktop");
    if let crate::runtime::RequestIdentity::Verified {
        ref mut attributes, ..
    } = planted
    {
        attributes.insert("subject_token".to_owned(), "planted".to_owned());
    }
    let subject_token = ["subject_token".to_owned()];
    assert_eq!(
        key(&desktop, &subject_token),
        key(&planted, &subject_token),
        "a planted subject attribute never reaches the key"
    );
}

/// Only an issuer that exchanges the stored sign-in solely at the IdP that
/// issued it may be handed one: any other is refused before the sign-in is
/// read, and the refusal is audited.
#[tokio::test]
async fn an_issuer_that_may_send_the_sign_in_anywhere_is_refused_before_it_is_read() {
    let (upstream, url) = untouchable_upstream().await;
    let mut fed = vault_fed(&url, SubjectToken::IdpRefreshToken);
    fed.upstream.auth.credential = Some("cred://stub.exchange/notion".to_owned());
    let h = harness(fed, FakeVault::new(Stored::Token("idp-rt-1")));
    let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(
        message.contains("`stub.exchange` may not be handed a stored sign-in")
            && message.contains(EXCHANGE),
        "{message}"
    );
    assert!(h.vault.asked().is_empty(), "the sign-in is never read");
    assert!(h.issued.lock().expect("issued lock").is_empty());
    assert_eq!(upstream_calls(&upstream).await, 0);
    let events = audited(&h.audited).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].action, "mcpg.federation.idp_subject_token");
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(events[0].details["outcome"], "refused");
    assert!(
        events[0].details["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("stub.exchange")),
        "{:?}",
        events[0].details
    );

    let mut unknown = vault_fed(&url, SubjectToken::IdpRefreshToken);
    unknown.upstream.auth.credential = Some("cred://no.such.issuer/notion".to_owned());
    let h = harness(unknown, FakeVault::new(Stored::Token("idp-rt-1")));
    let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
    assert!(message.contains("no.such.issuer"), "{message}");
    assert!(h.vault.asked().is_empty());
    assert_eq!(audited(&h.audited).await[0].details["outcome"], "refused");
}

/// An exchange the issuer refuses is a refusal of the stored sign-in, and
/// one that fails is unavailable: both are audited with the issuer's
/// reason, never the token, and neither counts as used.
#[tokio::test]
async fn a_failed_exchange_is_audited_as_refused_or_unavailable() {
    use mcpg_plugin_protocol::credential::CredentialError;
    for (failure, outcome, audit_outcome) in [
        (
            CredentialError::Misconfigured {
                reason: "the stored enterprise sign-in may only be exchanged at the IdP that \
                         issued it"
                    .to_owned(),
            },
            "refused",
            AuditOutcome::Denied,
        ),
        (
            CredentialError::Backend {
                reason: "the IdP token endpoint timed out".to_owned(),
            },
            "unavailable",
            AuditOutcome::Failure,
        ),
    ] {
        let (upstream, url) = untouchable_upstream().await;
        let h = harness(
            vault_fed(&url, SubjectToken::IdpRefreshToken),
            FakeVault::new(Stored::Token("idp-rt-secret")),
        );
        *h.refusal.lock().expect("refusal lock") = Some(failure.clone());
        let message = refusal(call(&h.engine, &signed_in_caller(), "gw-minted-at").await);
        assert!(
            message.contains("credential issue failed") && !message.contains("idp-rt-secret"),
            "{message}"
        );
        assert_eq!(upstream_calls(&upstream).await, 0);
        let events = audited(&h.audited).await;
        assert_eq!(events.len(), 1, "{outcome}: {events:?}");
        assert_eq!(events[0].details["outcome"], outcome);
        assert_eq!(events[0].outcome, audit_outcome, "{outcome}");
        let serialized = serde_json::to_string(&events[0]).expect("event serializes");
        assert!(
            serialized.contains(match failure {
                CredentialError::Misconfigured { .. } => "may only be exchanged",
                _ => "timed out",
            }),
            "the issuer's reason is audited: {serialized}"
        );
        assert!(!serialized.contains("idp-rt-secret"), "{serialized}");
    }
}

/// The caller's own-bearer mode strips every planted `subject_token*`
/// attribute too, so none can steer an issuer or the cache key.
#[test]
fn the_caller_bearer_identity_drops_every_planted_subject_attribute() {
    let identity = impersonation_identity(Some(&signed_in_caller()), "okta-at");
    let subject_attributes: Vec<(&String, &String)> = identity
        .attributes
        .iter()
        .filter(|(name, _)| name.starts_with("subject_token"))
        .collect();
    assert_eq!(
        subject_attributes,
        vec![(&"subject_token".to_owned(), &"okta-at".to_owned())]
    );
    assert_eq!(identity.attributes["acr"], "mfa");
}

#[test]
fn every_issuer_subject_attribute_is_reserved_by_its_prefix() {
    for name in ISSUER_SUBJECT_ATTRIBUTES {
        assert!(
            name.starts_with(idp_sessions::SUBJECT_ATTRIBUTE_PREFIX),
            "{name}"
        );
    }
}
