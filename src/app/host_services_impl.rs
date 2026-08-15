//! Gateway-side [`HostServices`] implementation.
//!
//! Bridges the trait calls that plugins make through `HostHandleRef`
//! into the gateway's already-existing infrastructure:
//!
//! - `resolve_secret` → `PluginRegistry::secret_provider_for_scheme(...).get(uri)`
//! - `issue_credential` → `PluginRegistry::credential_issuer(...).issue(...)`
//! - `config_snapshot` → `PluginRegistry::config_provider_for_scheme(...).snapshot(uri)`
//! - `audit_event` → routes to `tracing::info!` for now; the audit
//!   ledger sink wiring lands once `mcpg_audit::Ledger` is threaded
//!   into `AppState`
//! - `metric_emit` → `metrics::histogram!` / `counter!` / `gauge!`
//!   so plugin-emitted metrics blend with the rest of the gateway's
//!   Prometheus surface
//! - `span_start` / `span_end` / `span_event` → wired through to the
//!   `tracing` subscriber; spans appear in the configured trace sinks
//!
//! The struct is held behind a [`LateBoundHostServices`] so the
//! adapter construction sites can take an `Arc<dyn HostServices>`
//! that points at an unwired stub during early boot, and gets the
//! real `GatewayHostServices` swapped in once `PluginRegistry` is
//! final. Mirrors the existing `LateBoundBackendHost` pattern for
//! the binding-host trait.

use std::sync::Arc;

use async_trait::async_trait;
use mcpg_plugin_host::PluginRegistry;
use mcpg_plugin_host::host_services::{HostServices, MetricPoint};
use mcpg_plugin_protocol::audit::{AuditError, AuditEvent, AuditOutcome, AuditReceipt};
use mcpg_plugin_protocol::backend::{
    BackendHost, BackendHostError, BackendInvocationContext, CredentialRevocationCallback,
    CredentialRevocationSubscription, SecretRotationCallback, SecretRotationSubscription,
};
use mcpg_plugin_protocol::capability::Capability;
use mcpg_plugin_protocol::config::{ConfigError, ConfigSnapshot};
use mcpg_plugin_protocol::credential::{CredentialError, IssuedCredential};
use mcpg_plugin_protocol::secret::{SecretError, SecretValue};
use mcpg_plugin_protocol::types::PluginIdentity;

/// Concrete `HostServices` implementation wired through `PluginRegistry`.
///
/// Held inside an `Arc` and threaded through `LateBoundHostServices`
/// so adapter construction (which happens before the registry is
/// final) can take the late-bound wrapper and have it resolve to a
/// fully-wired `GatewayHostServices` once boot finishes.
///
/// `PluginRegistry`'s read-side methods all take `&self`, so the
/// registry handle is a plain `Arc<PluginRegistry>` — no extra lock
/// layer needed. Mutation happens behind the registry's own internal
/// locks during boot + reload; once handed to the host services it's
/// read-only for the bridge's lifetime.
pub struct GatewayHostServices {
    registry: Arc<PluginRegistry>,
    /// The same `GatewayBackendHost` the statically-linked backends get,
    /// so dynamically-loaded (cdylib) backends reach identical
    /// credential resolution / response cache / revocation + rotation
    /// fan-out through the host-FFI slots.
    backend_host: Arc<dyn BackendHost>,
}

impl GatewayHostServices {
    pub fn new(registry: Arc<PluginRegistry>, backend_host: Arc<dyn BackendHost>) -> Self {
        Self {
            registry,
            backend_host,
        }
    }

    /// Per-call capability enforcement: does the calling plugin
    /// (`alias`) hold a granted capability that covers `required`?
    ///
    /// Re-checked on every call, so a plugin can only reach the schemes/kinds
    /// the operator granted it. An unknown alias or empty grant ⇒ no cover ⇒
    /// refused (fail-closed).
    fn caller_covers(&self, alias: &str, required: &Capability) -> bool {
        self.registry
            .granted_capabilities_for_alias(alias)
            .iter()
            .any(|granted| granted.covers(required))
    }
}

/// Synthesize a minimal invocation context for the backend host services
/// that need one. The cdylib host-FFI carries only `alias` + identity at
/// the `register_profile`/cache call site (no full dispatch context), so
/// the synthesized ctx attributes to the plugin alias at depth 0.
fn synth_ctx(alias: &str, identity: Option<PluginIdentity>) -> BackendInvocationContext {
    BackendInvocationContext {
        parent_request_id: String::new(),
        session_id: None,
        initiating_backend: alias.to_owned(),
        depth: 0,
        identity,
    }
}

fn parse_scheme(uri: &str) -> Option<&str> {
    uri.split_once("://").map(|(s, _)| s)
}

#[async_trait]
impl HostServices for GatewayHostServices {
    async fn resolve_secret(&self, alias: &str, uri: &str) -> Result<SecretValue, SecretError> {
        let scheme = parse_scheme(uri).ok_or_else(|| SecretError::InvalidReference {
            message: format!("secret uri {uri:?} has no scheme"),
        })?;
        // The caller must hold SecretsRead for this scheme.
        let required = Capability::SecretsRead {
            schemes: vec![scheme.to_owned()],
        };
        if !self.caller_covers(alias, &required) {
            tracing::warn!(
                plugin_alias = %alias,
                scheme = %scheme,
                "host resolve_secret denied: plugin lacks secrets_read for this scheme"
            );
            return Err(SecretError::PermissionDenied);
        }
        // Resource scope (layered on TOP of the scheme cap): the cap
        // authorizes the SCHEME, but a plugin may only read the concrete
        // resources its own operator-authored config references. So holding
        // `SecretsRead{env}` no longer lets a compromised cdylib read EVERY
        // env var (`env://AWS_SECRET_ACCESS_KEY`) — only the `env://NAME`s its
        // config named. Boot-derived, fail-closed for unlisted resources.
        if !self.registry.resource_resolve_allowed(alias, uri) {
            tracing::warn!(
                plugin_alias = %alias,
                scheme = %scheme,
                "host resolve_secret denied: resource not in the plugin's \
                 config-origin allowlist"
            );
            metrics::counter!(
                "mcpg_host_resolve_secret_denied_total",
                "alias" => alias.to_owned(),
                "scheme" => scheme.to_owned(),
            )
            .increment(1);
            return Err(SecretError::PermissionDenied);
        }
        let provider = self
            .registry
            .secret_provider_for_scheme(scheme)
            .ok_or_else(|| SecretError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            })?;
        provider.get(uri).await
    }

    async fn issue_credential(
        &self,
        alias: &str,
        uri: &str,
        identity: PluginIdentity,
    ) -> Result<IssuedCredential, CredentialError> {
        // Per-call gate, in two stages:
        //   1. Family-level fail-fast — the caller must hold SOME
        //      credential_issue grant. Cheap, and keeps a clear error for
        //      the common "plugin can't mint credentials at all" case
        //      without first resolving the issuer.
        //   2. Kind-precise gate (below, after the issuer resolves) — the
        //      caller must hold credential_issue for THIS issuer's kind.
        let family = Capability::CredentialIssue { kinds: vec![] };
        if !self.caller_covers(alias, &family) {
            tracing::warn!(
                plugin_alias = %alias,
                "host issue_credential denied: plugin lacks the credential_issue capability"
            );
            return Err(CredentialError::NotAuthorized {
                reason: format!("plugin '{alias}' is not granted the credential_issue capability"),
            });
        }
        // `cred://<plugin_id>/<target>` — extract the issuer plugin id
        // and target. Issuer-specific config is empty here because
        // per-call config flows through the gateway's resolver, not
        // through HostServices.
        let after_scheme =
            uri.strip_prefix("cred://")
                .ok_or_else(|| CredentialError::Misconfigured {
                    reason: format!("credential uri {uri:?} must start with cred://"),
                })?;
        let (plugin_id, target) =
            after_scheme
                .split_once('/')
                .ok_or_else(|| CredentialError::Misconfigured {
                    reason: format!("credential uri {uri:?} missing /<target>"),
                })?;
        let issuer = self.registry.credential_issuer(plugin_id).ok_or_else(|| {
            CredentialError::Misconfigured {
                reason: format!("no credential_issuer plugin id={plugin_id:?}"),
            }
        })?;
        // Kind-precise gate: the caller must be granted credential_issue
        // for the kind THIS issuer mints, not merely the family. The grant
        // is matched by superset (`CredentialIssue{kinds}` covers the
        // required kind iff it lists it), so an empty-kinds grant — useless
        // by construction — fails closed here.
        let kind = issuer.credential_kind();
        let required = Capability::CredentialIssue {
            kinds: vec![kind.clone()],
        };
        if !self.caller_covers(alias, &required) {
            tracing::warn!(
                plugin_alias = %alias,
                credential_kind = %kind,
                "host issue_credential denied: plugin lacks credential_issue for this kind"
            );
            return Err(CredentialError::NotAuthorized {
                reason: format!(
                    "plugin '{alias}' is not granted credential_issue for kind '{kind}'"
                ),
            });
        }
        let cfg = serde_json::Value::Object(serde_json::Map::new());
        issuer.issue(&identity, target, &cfg).await
    }

    async fn config_snapshot(&self, alias: &str, uri: &str) -> Result<ConfigSnapshot, ConfigError> {
        let scheme = parse_scheme(uri).ok_or_else(|| ConfigError::InvalidReference {
            message: format!("config uri {uri:?} has no scheme"),
        })?;
        // The caller must hold ConfigRead for this scheme.
        let required = Capability::ConfigRead {
            schemes: vec![scheme.to_owned()],
        };
        if !self.caller_covers(alias, &required) {
            tracing::warn!(
                plugin_alias = %alias,
                scheme = %scheme,
                "host config_snapshot denied: plugin lacks config_read for this scheme"
            );
            return Err(ConfigError::PermissionDenied);
        }
        // Resource scope (layered on TOP of the scheme cap): the plugin may
        // only snapshot the concrete config resources its own config
        // references. Boot-derived, fail-closed for unlisted resources.
        if !self.registry.resource_resolve_allowed(alias, uri) {
            tracing::warn!(
                plugin_alias = %alias,
                scheme = %scheme,
                "host config_snapshot denied: resource not in the plugin's \
                 config-origin allowlist"
            );
            metrics::counter!(
                "mcpg_host_config_snapshot_denied_total",
                "alias" => alias.to_owned(),
                "scheme" => scheme.to_owned(),
            )
            .increment(1);
            return Err(ConfigError::PermissionDenied);
        }
        let provider = self
            .registry
            .config_provider_for_scheme(scheme)
            .ok_or_else(|| ConfigError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            })?;
        provider.snapshot(uri).await
    }

    async fn audit_event(
        &self,
        alias: &str,
        event: AuditEvent,
    ) -> Result<AuditReceipt, AuditError> {
        // Until the audit ledger is plumbed into AppState, route to
        // tracing so the event lands in whatever subscriber the
        // operator has wired (file, otlp, control plane). The receipt
        // is synthesized from the event id + a fixed sink_plugin_id
        // so plugins still see a coherent return value.
        let outcome_label = match event.outcome {
            AuditOutcome::Success => "success",
            AuditOutcome::Failure => "failure",
            AuditOutcome::Partial => "partial",
            AuditOutcome::Denied => "denied",
        };
        tracing::info!(
            target: "mcpg.audit",
            plugin_alias = %alias,
            event_id = %event.event_id,
            action = %event.action,
            outcome = outcome_label,
            "plugin-emitted audit event"
        );
        Ok(AuditReceipt {
            sink_id: "dev.mcpg.builtin.audit.tracing".to_owned(),
            persisted_at: event.occurred_at,
            durable_hash: String::new(),
        })
    }

    fn metric_emit(&self, alias: &str, point: MetricPoint) {
        // Plugin-supplied label values are attacker-chosen strings that land
        // in the (long-retained) metrics store; redact any resolved
        // `scheme://user:pass@host` before emission so a compromised plugin
        // can't exfiltrate a secret it handled through a metric label.
        fn scrub(labels: Vec<(String, String)>) -> Vec<(String, String)> {
            labels
                .into_iter()
                .map(|(k, v)| (k, mcpg_plugin_protocol::redact::redact_in_text(&v)))
                .collect()
        }
        match point {
            MetricPoint::Counter {
                name,
                value,
                labels,
            } => {
                let mut labs: Vec<(String, String)> = vec![("alias".into(), alias.to_owned())];
                labs.extend(scrub(labels));
                metrics::counter!(name, &labs[..]).increment(value);
            }
            MetricPoint::Gauge {
                name,
                value,
                labels,
            } => {
                let mut labs: Vec<(String, String)> = vec![("alias".into(), alias.to_owned())];
                labs.extend(scrub(labels));
                metrics::gauge!(name, &labs[..]).set(value);
            }
            MetricPoint::Histogram {
                name,
                value,
                labels,
            } => {
                let mut labs: Vec<(String, String)> = vec![("alias".into(), alias.to_owned())];
                labs.extend(scrub(labels));
                metrics::histogram!(name, &labs[..]).record(value);
            }
        }
    }

    fn span_start(&self, alias: &str, name: &str, mut attrs: serde_json::Value) -> u64 {
        // Plugin spans land in the same tracing subscriber as the
        // gateway's own spans. We don't try to thread span_id
        // semantics through the tracing crate (it has its own id
        // space) — instead we emit a single info-level event that
        // carries the plugin alias + span name + attrs JSON. The
        // returned id is opaque-to-plugins (0 = "not tracked"); the
        // SDK treats it as a token, not an addressable handle.
        // Attrs are plugin-chosen and reach a long-retained sink — redact
        // any embedded `scheme://user:pass@host` before emitting.
        mcpg_plugin_protocol::redact::redact_value(&mut attrs);
        tracing::info!(
            target: "mcpg.plugin.span",
            plugin_alias = %alias,
            span_name = %name,
            attrs = %attrs,
            "plugin span_start"
        );
        0
    }

    fn span_end(&self, _span_id: u64) {
        // No tracing-crate handle to close; the SDK's `span_end` is
        // best-effort and the event already landed at start.
    }

    fn span_event(&self, _span_id: u64, name: &str, mut attrs: serde_json::Value) {
        mcpg_plugin_protocol::redact::redact_value(&mut attrs);
        tracing::info!(
            target: "mcpg.plugin.span",
            event_name = %name,
            attrs = %attrs,
            "plugin span_event"
        );
    }

    // ── Backend host services — delegate to GatewayBackendHost ───
    async fn invoke_tool(
        &self,
        ctx: &BackendInvocationContext,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value, BackendHostError> {
        // A plugin-initiated `invoke_tool` is by definition a CHILD dispatch,
        // so its depth must be >= 1 — never the 0 a fresh top-level request
        // carries. Clamp a plugin-supplied depth up to at least 1 so a
        // compromised cdylib cannot reset the recursion/cycle cap to 0 and
        // drive unbounded nested invocation. `GatewayBackendHost::invoke_tool`
        // enforces the cap on the resulting depth (parity with static
        // backends, which build the same ctx — but at a depth the gateway,
        // not the plugin, set).
        let mut ctx = ctx.clone();
        ctx.depth = ctx.depth.max(1);
        self.backend_host.invoke_tool(&ctx, tool_name, args).await
    }

    async fn resolve_credentials(
        &self,
        alias: &str,
        value: &mut serde_json::Value,
        identity: Option<PluginIdentity>,
    ) -> Result<usize, BackendHostError> {
        // Config-origin gate: a plugin may resolve only the exact
        // `cred://<issuer>/<target>` refs its OWN operator-authored config
        // references (recorded at boot). Gating the full `(issuer, target)`
        // pair — not merely the issuer — means a plugin that legitimately
        // references `cred://vault-pg/orders-ro` still cannot launder
        // `cred://vault-pg/payroll-rw` on the same issuer. A compromised
        // cdylib that hands the host any unreferenced ref is refused, closing
        // the host-FFI credential-exfil path that otherwise bypassed the
        // `cred://`-is-config-origin invariant. The plugin-supplied identity
        // is NOT trusted to authorize this; the boot-derived allowlist is.
        for key in mcpg_plugin_host::credential_resolver::collect_cred_refs(value) {
            if !self.registry.cred_resolve_ref_key_allowed(alias, &key) {
                tracing::warn!(
                    plugin_alias = %alias,
                    cred_ref = %key,
                    "host resolve_credentials denied: cred ref not in the plugin's \
                     config-origin allowlist"
                );
                metrics::counter!(
                    "mcpg_host_resolve_credentials_denied_total",
                    "alias" => alias.to_owned(),
                )
                .increment(1);
                return Err(BackendHostError::PolicyDenied {
                    tool_name: format!("cred://{key}"),
                });
            }
        }
        let ctx = synth_ctx(alias, identity);
        self.backend_host.resolve_credentials(&ctx, value).await
    }

    async fn cache_get(
        &self,
        alias: &str,
        key: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let ctx = synth_ctx(alias, None);
        self.backend_host.cache_get(&ctx, key).await
    }

    async fn fetch_content(
        &self,
        alias: &str,
        uri: &str,
    ) -> Result<Option<bytes::Bytes>, BackendHostError> {
        let ctx = synth_ctx(alias, None);
        self.backend_host.fetch_content(&ctx, uri).await
    }

    async fn store_content(
        &self,
        alias: &str,
        bytes: bytes::Bytes,
        mime_type: String,
        ttl: Option<std::time::Duration>,
    ) -> Result<mcpg_plugin_protocol::backend::BackendResource, BackendHostError> {
        let ctx = synth_ctx(alias, None);
        self.backend_host
            .store_content(&ctx, bytes, mime_type, ttl)
            .await
    }

    fn subscribe_credential_revoked(
        &self,
        _alias: &str,
        cb: CredentialRevocationCallback,
    ) -> CredentialRevocationSubscription {
        self.backend_host.subscribe_credential_revoked(cb)
    }

    fn subscribe_secret_rotation(
        &self,
        _alias: &str,
        cb: SecretRotationCallback,
    ) -> SecretRotationSubscription {
        self.backend_host.subscribe_secret_rotation(cb)
    }
}

#[cfg(test)]
mod tests {
    //! Kind-precise `issue_credential` enforcement. The host
    //! callback must grant a credential only when the caller holds
    //! `CredentialIssue` for the *kind the resolved issuer mints*, not
    //! merely the family. The issuer's kind comes from
    //! `CredentialIssuer::credential_kind()` (default = manifest id).

    use super::*;
    use mcpg_plugin_protocol::PluginTier;
    use mcpg_plugin_protocol::credential::CredentialIssuer;
    use mcpg_plugin_protocol::manifest::{PluginClass, PluginManifest};

    /// Stub issuer that mints a fixed credential and reports a kind via
    /// either the trait default (manifest id) or an explicit override.
    struct StubIssuer {
        manifest: PluginManifest,
        kind_override: Option<String>,
    }

    #[async_trait]
    impl CredentialIssuer for StubIssuer {
        fn manifest(&self) -> &PluginManifest {
            &self.manifest
        }
        fn credential_kind(&self) -> String {
            self.kind_override
                .clone()
                .unwrap_or_else(|| self.manifest.id.clone())
        }
        async fn issue(
            &self,
            _identity: &PluginIdentity,
            _target: &str,
            _config: &serde_json::Value,
        ) -> Result<IssuedCredential, CredentialError> {
            Ok(IssuedCredential::from_value("token-123", 3600))
        }
    }

    fn issuer_manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            version: "0.1.0".into(),
            name: format!("Stub issuer {id}"),
            plugin_class: PluginClass::CredentialIssuer,
            protocol_version: "1.0".into(),
            license: None,
            required_capabilities: vec![],
            tags: vec![],
            provides: vec![],
            provides_schemes: vec![],
            module_path_prefix: ::std::module_path!()
                .split("::")
                .next()
                .unwrap_or("")
                .to_owned(),
            backend_profile: None,
        }
    }

    fn identity() -> PluginIdentity {
        PluginIdentity {
            kind: "verified".into(),
            trust_level: "verified".into(),
            subject_id: Some("user-1".into()),
            auth_provider: Some("idp".into()),
            issuer: Some("https://idp.example.com".into()),
            roles: vec![],
            groups: vec![],
            scopes: vec![],
            attributes: std::collections::BTreeMap::new(),
        }
    }

    fn cred_issue(kinds: &[&str]) -> Capability {
        Capability::CredentialIssue {
            kinds: kinds.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// Build host services with one stub issuer + the given per-alias grants.
    fn services_with(
        issuer_id: &str,
        kind_override: Option<String>,
        grants: &[(&str, Capability)],
    ) -> GatewayHostServices {
        let mut reg = PluginRegistry::new();
        reg.register_credential_issuer(
            Arc::new(StubIssuer {
                manifest: issuer_manifest(issuer_id),
                kind_override,
            }),
            PluginTier::Native,
        )
        .unwrap();
        for (alias, cap) in grants {
            reg.record_granted_capabilities((*alias).to_owned(), vec![cap.clone()]);
        }
        // `LateBoundBackendHost::new()` already returns an `Arc<Self>`; it's an
        // unwired no-op stub here (issue_credential never touches backend_host).
        let backend_host: Arc<dyn BackendHost> = mcpg_plugin_protocol::LateBoundBackendHost::new();
        GatewayHostServices::new(Arc::new(reg), backend_host)
    }

    #[tokio::test]
    async fn allows_caller_granted_the_issuer_kind() {
        let svc = services_with(
            "dev.test.cred.alpha",
            None,
            &[("caller-ok", cred_issue(&["dev.test.cred.alpha"]))],
        );
        let res = svc
            .issue_credential("caller-ok", "cred://dev.test.cred.alpha/role-x", identity())
            .await;
        assert!(res.is_ok(), "expected Ok, got {res:?}");
    }

    #[tokio::test]
    async fn denies_caller_granted_a_different_kind() {
        // Passes the family fail-fast (holds *some* credential_issue) but is
        // refused by the kind-precise gate.
        let svc = services_with(
            "dev.test.cred.alpha",
            None,
            &[("caller-wrong", cred_issue(&["dev.test.cred.beta"]))],
        );
        let res = svc
            .issue_credential(
                "caller-wrong",
                "cred://dev.test.cred.alpha/role-x",
                identity(),
            )
            .await;
        assert!(
            matches!(res, Err(CredentialError::NotAuthorized { .. })),
            "expected NotAuthorized, got {res:?}"
        );
    }

    #[tokio::test]
    async fn denies_caller_with_no_credential_issue_grant() {
        let svc = services_with("dev.test.cred.alpha", None, &[]);
        let res = svc
            .issue_credential(
                "caller-none",
                "cred://dev.test.cred.alpha/role-x",
                identity(),
            )
            .await;
        assert!(matches!(res, Err(CredentialError::NotAuthorized { .. })));
    }

    #[tokio::test]
    async fn empty_kinds_grant_fails_closed() {
        // A credential_issue grant with empty kinds clears the family gate
        // but matches no specific kind — must fail closed.
        let svc = services_with(
            "dev.test.cred.alpha",
            None,
            &[("caller-empty", cred_issue(&[]))],
        );
        let res = svc
            .issue_credential(
                "caller-empty",
                "cred://dev.test.cred.alpha/role-x",
                identity(),
            )
            .await;
        assert!(matches!(res, Err(CredentialError::NotAuthorized { .. })));
    }

    #[tokio::test]
    async fn kind_comes_from_credential_kind_override_not_plugin_id() {
        // Issuer overrides credential_kind() to a shared abstract kind.
        // A caller granted that shared kind is authorized; a caller granted
        // only the plugin id (the default kind) is now refused — proving the
        // required kind is sourced from credential_kind(), not the uri.
        let svc = services_with(
            "dev.test.cred.alpha",
            Some("oauth_token".to_owned()),
            &[
                ("caller-shared", cred_issue(&["oauth_token"])),
                ("caller-byid", cred_issue(&["dev.test.cred.alpha"])),
            ],
        );
        assert!(
            svc.issue_credential("caller-shared", "cred://dev.test.cred.alpha/r", identity())
                .await
                .is_ok(),
            "caller granted the overridden kind must be allowed"
        );
        let by_id = svc
            .issue_credential("caller-byid", "cred://dev.test.cred.alpha/r", identity())
            .await;
        assert!(
            matches!(by_id, Err(CredentialError::NotAuthorized { .. })),
            "caller granted only the plugin id must be refused once kind is overridden: {by_id:?}"
        );
    }

    /// Build host services with a config-origin `cred://` allowlist recorded
    /// for one alias (the boot loop derives this from the entry's config).
    /// `refs` are full `<issuer>/<target>` keys; both the issuer-level and the
    /// exact-ref allowlists are recorded, mirroring the boot loop.
    fn services_with_cred_allowlist(alias: &str, refs: &[&str]) -> GatewayHostServices {
        let mut reg = PluginRegistry::new();
        let issuers: std::collections::HashSet<String> = refs
            .iter()
            .filter_map(|r| r.split_once('/').map(|(i, _)| i.to_owned()))
            .collect();
        reg.record_cred_resolve_allowlist(alias.to_owned(), issuers);
        reg.record_cred_resolve_ref_allowlist(
            alias.to_owned(),
            refs.iter().map(|s| (*s).to_owned()).collect(),
        );
        let backend_host: Arc<dyn BackendHost> = mcpg_plugin_protocol::LateBoundBackendHost::new();
        GatewayHostServices::new(Arc::new(reg), backend_host)
    }

    #[tokio::test]
    async fn resolve_credentials_denies_issuer_outside_config_allowlist() {
        // The plugin's config references `vault-pg/orders`, but it hands the
        // host an arbitrary `cred://vault-admin/…` — the exfil path. Must be
        // refused before any resolution, regardless of the (plugin-supplied)
        // identity.
        let svc = services_with_cred_allowlist("backend-a", &["vault-pg/orders"]);
        let mut value = serde_json::json!({ "password": "cred://vault-admin/root" });
        let res = svc.resolve_credentials("backend-a", &mut value, None).await;
        assert!(
            matches!(res, Err(BackendHostError::PolicyDenied { .. })),
            "issuer outside the config-origin allowlist must be denied: {res:?}"
        );
        // The value is left untouched (no resolution happened).
        assert_eq!(value["password"], "cred://vault-admin/root");
    }

    #[tokio::test]
    async fn resolve_credentials_denies_unreferenced_target_on_referenced_issuer() {
        // CC-3: the plugin references `vault-pg/orders-ro`, so the issuer
        // `vault-pg` IS in its config — but a different target on that same
        // issuer (`payroll-rw`) was never referenced and must still be denied.
        let svc = services_with_cred_allowlist("backend-a", &["vault-pg/orders-ro"]);
        let mut value = serde_json::json!({ "password": "cred://vault-pg/payroll-rw" });
        let res = svc.resolve_credentials("backend-a", &mut value, None).await;
        assert!(
            matches!(res, Err(BackendHostError::PolicyDenied { .. })),
            "unreferenced target on a referenced issuer must be denied: {res:?}"
        );
        assert_eq!(value["password"], "cred://vault-pg/payroll-rw");
    }

    #[tokio::test]
    async fn resolve_credentials_denies_unknown_alias_fail_closed() {
        // An alias with no recorded allowlist (e.g. a plugin that referenced
        // no creds in config) cannot resolve anything.
        let svc = services_with_cred_allowlist("backend-a", &["vault-pg/orders"]);
        let mut value = serde_json::json!({ "password": "cred://vault-pg/orders" });
        let res = svc
            .resolve_credentials("unknown-alias", &mut value, None)
            .await;
        assert!(
            matches!(res, Err(BackendHostError::PolicyDenied { .. })),
            "unknown alias must fail closed: {res:?}"
        );
    }

    /// Build host services granting `SecretsRead{scheme}` AND recording a
    /// config-origin resource allowlist for one alias (mirrors the boot loop).
    fn services_with_secret_scope(
        alias: &str,
        scheme: &str,
        resources: &[&str],
    ) -> GatewayHostServices {
        let mut reg = PluginRegistry::new();
        reg.record_granted_capabilities(
            alias.to_owned(),
            vec![Capability::SecretsRead {
                schemes: vec![scheme.to_owned()],
            }],
        );
        reg.record_resource_resolve_allowlist(
            alias.to_owned(),
            resources.iter().map(|s| (*s).to_owned()).collect(),
        );
        let backend_host: Arc<dyn BackendHost> = mcpg_plugin_protocol::LateBoundBackendHost::new();
        GatewayHostServices::new(Arc::new(reg), backend_host)
    }

    #[tokio::test]
    async fn resolve_secret_denies_offallowlist_resource_despite_scheme_cap() {
        // The plugin holds SecretsRead{env} and references `env://ALLOWED_KEY`
        // in config — but tries to read a DIFFERENT env var. The scheme cap is
        // satisfied; the resource gate must still deny (CS-1).
        let svc = services_with_secret_scope("backend-a", "env", &["env://ALLOWED_KEY"]);
        let denied = svc
            .resolve_secret("backend-a", "env://AWS_SECRET_ACCESS_KEY")
            .await;
        assert!(
            matches!(denied, Err(SecretError::PermissionDenied)),
            "off-allowlist env var must be denied even with the scheme cap: {denied:?}"
        );
        // The config-referenced resource passes the resource gate — no provider
        // is bound here, so it surfaces as UnsupportedScheme rather than
        // PermissionDenied, which proves the gate let it through.
        let passed = svc.resolve_secret("backend-a", "env://ALLOWED_KEY").await;
        assert!(
            !matches!(passed, Err(SecretError::PermissionDenied)),
            "a config-referenced resource must pass the resource gate: {passed:?}"
        );
    }

    #[tokio::test]
    async fn resolve_secret_denies_when_scheme_cap_missing_even_if_allowlisted() {
        // Resource IS allowlisted, but the alias holds no SecretsRead grant —
        // the scheme cap gate denies first (fail-closed layering).
        let mut reg = PluginRegistry::new();
        reg.record_resource_resolve_allowlist(
            "backend-a".to_owned(),
            std::iter::once("env://ALLOWED_KEY".to_owned()).collect(),
        );
        let backend_host: Arc<dyn BackendHost> = mcpg_plugin_protocol::LateBoundBackendHost::new();
        let svc = GatewayHostServices::new(Arc::new(reg), backend_host);
        let denied = svc.resolve_secret("backend-a", "env://ALLOWED_KEY").await;
        assert!(
            matches!(denied, Err(SecretError::PermissionDenied)),
            "missing scheme cap must deny regardless of the resource allowlist: {denied:?}"
        );
    }

    #[tokio::test]
    async fn resolve_credentials_allows_configured_ref_past_the_gate() {
        // A `cred://vault-pg/orders` matching the alias's config-origin
        // (issuer, target) allowlist passes the gate and delegates to the
        // backend host (here the unwired stub) — proving the gate did NOT
        // deny it.
        let svc = services_with_cred_allowlist("backend-a", &["vault-pg/orders"]);
        let mut value = serde_json::json!({ "password": "cred://vault-pg/orders" });
        let res = svc.resolve_credentials("backend-a", &mut value, None).await;
        assert!(
            !matches!(res, Err(BackendHostError::PolicyDenied { .. })),
            "a configured (issuer,target) ref must pass the config-origin gate: {res:?}"
        );
    }
}
