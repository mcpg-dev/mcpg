//! TLS plumbing for the HTTP transport: server-config building,
//! peer-cert extraction, and the rustls → `RequestMetadata.tls`
//! bridge.
//!
//! This module exists so the HTTP transport stays focused on
//! routing while the (somewhat tedious) TLS wiring lives in one
//! place. It also feeds the X.509-SVID source in
//! `dev.mcpg.identity.workload`.
//!
//! ## Flow
//!
//! 1. [`build_server_config`] reads the operator's `tls.*` config
//!    block and constructs a `rustls::ServerConfig` with the
//!    server cert + key, and (when `client_cert_required` is set)
//!    a `WebPkiClientVerifier` against the operator-supplied CA
//!    bundle.
//! 2. [`McpgTlsAcceptor`] wraps `axum_server::tls_rustls::RustlsAcceptor`
//!    and inspects the freshly-handshaken `tokio_rustls::TlsStream`
//!    for peer certs. It builds a [`TlsInfo`] (parsed once, shared
//!    by every request on this connection) and wraps the
//!    per-connection service with [`InjectTlsInfo`] so each request
//!    gets the metadata via `Extensions`.
//! 3. The HTTP request handler reads `req.extensions().get::<TlsInfoArc>()`
//!    via [`request_tls_info`] and threads it into
//!    `RequestMetadata.tls`. Identity plugins (mtls direct_mtls,
//!    workload x509_svid) consume from there.

use std::fs;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use axum::http::Request;
use mcpg_plugin_protocol::types::TlsInfo;
use rustls::ServerConfig;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower::Service;
use x509_parser::prelude::FromDer;

use crate::config::{ClientCertMode, TlsConfig};

pub use axum_server::tls_rustls::RustlsConfig;

/// Cheaply-cloneable wrapper around the per-connection TlsInfo.
/// Stored in request extensions; the HTTP handler unwraps it via
/// [`request_tls_info`].
pub type TlsInfoArc = Arc<TlsInfo>;

/// ALPN protocols offered by the gateway's HTTPS listener. Order
/// matters — clients pick the first protocol they support, so
/// `h2` precedes `http/1.1`.
const ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Install the aws-lc-rs `CryptoProvider` as the rustls process
/// default. Idempotent; calling it from anywhere in the gateway is
/// safe. We need an explicit call because the workspace pulls
/// multiple rustls users (axum-server, reqwest, hyper-rustls) and
/// rustls 0.23 refuses to auto-pick a provider when more than one
/// feature is enabled — install_default() is the canonical
/// remedy.
pub fn install_default_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Ignore the result — `install_default` returns Err if
        // another caller already installed a provider, which is
        // fine for our purposes (whatever-was-installed wins).
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Build a `rustls::ServerConfig` from the operator's TLS block.
///
/// Returns the config wrapped in `Arc` so axum-server's
/// `RustlsConfig::from_config` can adopt it without re-cloning.
/// Map the operator's `min_tls_version` to the rustls protocol-version set
/// the server offers. `"1.3"` restricts to TLS 1.3 only; `"1.2"` permits
/// TLS 1.2 and 1.3. An unknown value is rejected so a misconfiguration
/// fails loud at boot rather than silently leaving TLS 1.2 negotiable.
fn tls_protocol_versions(
    min: &str,
) -> Result<&'static [&'static rustls::SupportedProtocolVersion]> {
    static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static TLS12_AND_13: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS12, &rustls::version::TLS13];
    match min.trim() {
        "1.3" => Ok(TLS13_ONLY),
        "1.2" => Ok(TLS12_AND_13),
        other => Err(anyhow::anyhow!(
            "server.tls.min_tls_version must be \"1.2\" or \"1.3\", got {other:?}"
        )),
    }
}

pub fn build_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>> {
    install_default_crypto_provider();

    let cert_chain = load_cert_chain(&tls.cert_path)
        .with_context(|| format!("loading server cert from {}", tls.cert_path))?;
    let key = load_private_key(&tls.key_path)
        .with_context(|| format!("loading server key from {}", tls.key_path))?;

    let builder =
        ServerConfig::builder_with_protocol_versions(tls_protocol_versions(&tls.min_tls_version)?);

    let mut server_config = match tls.client_cert_required {
        ClientCertMode::None => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?,
        ClientCertMode::Optional | ClientCertMode::Mandatory => {
            let ca_path = tls
                .client_ca_certs_path
                .as_deref()
                .expect("config validator guarantees a CA path when client_cert_required != None");
            let mut roots = rustls::RootCertStore::empty();
            for ca in load_cert_chain(ca_path)
                .with_context(|| format!("loading client CA bundle from {ca_path}"))?
            {
                roots
                    .add(ca)
                    .map_err(|e| anyhow::anyhow!("client CA bundle has an invalid cert: {e}"))?;
            }
            let verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = match tls.client_cert_required {
                ClientCertMode::Optional => verifier_builder.allow_unauthenticated(),
                ClientCertMode::Mandatory => verifier_builder,
                ClientCertMode::None => unreachable!(),
            };
            let verifier = verifier
                .build()
                .map_err(|e| anyhow::anyhow!("WebPkiClientVerifier build: {e}"))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(cert_chain, key)
                .map_err(|e| anyhow::anyhow!("rustls server config: {e}"))?
        }
    };

    server_config.alpn_protocols = ALPN_PROTOCOLS.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(server_config))
}

fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path)?;
    let mut reader = std::io::BufReader::new(bytes.as_slice());
    let chain: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if chain.is_empty() {
        return Err(anyhow::anyhow!(
            "no PEM certificates found in {path} — file must contain at least one CERTIFICATE block"
        ));
    }
    Ok(chain)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let bytes = fs::read(path)?;
    let mut reader = std::io::BufReader::new(bytes.as_slice());
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no PEM private key found in {path} — file must contain a PRIVATE KEY block"
        )
    })
}

/// Acceptor wrapper that pulls the peer cert chain off each
/// freshly-handshaken TLS stream and stamps a [`TlsInfo`] onto the
/// per-connection service via [`InjectTlsInfo`].
#[derive(Clone)]
pub struct McpgTlsAcceptor<A> {
    inner: A,
}

impl<A> McpgTlsAcceptor<A> {
    pub fn new(inner: A) -> Self {
        Self { inner }
    }
}

/// Best-effort transport peer address off the raw accepted IO, captured
/// BEFORE the TLS handshake consumes the stream. Implemented for the real
/// `TcpStream`; the blanket `None` default keeps the acceptor generic over
/// test/in-memory IO types.
pub trait RemoteAddr {
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }
}

impl RemoteAddr for tokio::net::TcpStream {
    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.peer_addr().ok()
    }
}

impl<A, I, S> axum_server::accept::Accept<I, S> for McpgTlsAcceptor<A>
where
    A: axum_server::accept::Accept<I, S, Stream = TlsStream<I>> + Send + Sync,
    A::Future: Send + 'static,
    A::Service: Send + 'static,
    I: AsyncRead + AsyncWrite + RemoteAddr + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<I>;
    type Service = InjectTlsInfo<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        // Capture the transport peer BEFORE the handshake takes the stream —
        // the TLS path has no axum `into_make_service_with_connect_info`, so
        // this is where `ConnectInfo` (used by the anonymous per-IP rate
        // limiter) comes from on HTTPS.
        let peer = stream.remote_addr();
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = fut.await?;
            let tls_info = build_tls_info(&stream);
            Ok((
                stream,
                InjectTlsInfo {
                    inner: service,
                    tls_info: tls_info.map(Arc::new),
                    peer,
                },
            ))
        })
    }
}

/// Tower `Service` shim that injects the per-connection
/// [`TlsInfoArc`] + transport peer address into every incoming
/// request's extensions. The peer rides as
/// `axum::extract::ConnectInfo<SocketAddr>` — the SAME extension
/// axum's `into_make_service_with_connect_info` installs on the
/// plain-HTTP path, so downstream extraction is transport-uniform.
#[derive(Clone)]
pub struct InjectTlsInfo<S> {
    inner: S,
    tls_info: Option<TlsInfoArc>,
    peer: Option<std::net::SocketAddr>,
}

impl<S> InjectTlsInfo<S> {
    /// Snapshot of the per-connection [`TlsInfoArc`] this shim
    /// stamps onto incoming requests, or `None` when the
    /// connection has neither SNI nor a peer cert worth
    /// surfacing. Public for integration tests; production code
    /// reads it off `req.extensions()` rather than poking the
    /// service directly.
    pub fn tls_info_for_test(&self) -> Option<&TlsInfoArc> {
        self.tls_info.as_ref()
    }
}

impl<S, B> Service<Request<B>> for InjectTlsInfo<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        if let Some(info) = &self.tls_info {
            req.extensions_mut().insert(info.clone());
        }
        if let Some(peer) = self.peer {
            req.extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
        }
        self.inner.call(req)
    }
}

/// Pull a [`TlsInfoArc`] out of an incoming request's extensions,
/// if present. Plain HTTP requests (no TLS) and TLS requests
/// without a presented client cert both yield `None` from the
/// caller's perspective on the `client_cert_*` fields — but the
/// `TlsInfo` is still attached so plugins can read SNI / negotiated
/// cipher etc. once those are surfaced.
pub fn request_tls_info<B>(req: &Request<B>) -> Option<TlsInfoArc> {
    req.extensions().get::<TlsInfoArc>().cloned()
}

/// Construct a [`TlsInfo`] from a freshly-handshaken
/// `tokio_rustls::server::TlsStream`. Returns `None` when the
/// underlying rustls connection has no SNI and no client cert
/// chain — every other path returns a `Some(info)` even when
/// `client_cert_present` is false (operators may still want to
/// see SNI in the audit log).
pub fn build_tls_info<I>(stream: &TlsStream<I>) -> Option<TlsInfo> {
    let (_io, conn) = stream.get_ref();
    let sni = conn.server_name().map(str::to_owned);
    let chain: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
        .unwrap_or_default();
    if sni.is_none() && chain.is_empty() {
        return None;
    }
    Some(tls_info_from_chain(sni, chain))
}

/// Build a [`TlsInfo`] from a (possibly empty) peer cert chain plus
/// optional SNI. Public for unit tests that want to bypass the
/// rustls dance.
pub fn tls_info_from_chain(sni: Option<String>, chain: Vec<CertificateDer<'static>>) -> TlsInfo {
    if chain.is_empty() {
        return TlsInfo {
            sni,
            client_cert_present: false,
            client_cert_chain_der: Vec::new(),
            ..Default::default()
        };
    }
    let chain_bytes: Vec<Vec<u8>> = chain.iter().map(|c| c.as_ref().to_vec()).collect();
    let chain_sha256: Vec<String> = chain_bytes.iter().map(|b| sha256_hex(b)).collect();

    // Parse the leaf for the rest of the fields. Failures are not
    // fatal — the gateway already accepted the chain at the rustls
    // verifier level, so a parser hiccup just leaves the cosmetic
    // fields (DN, SAN, validity) empty rather than tearing the
    // connection down.
    let leaf_bytes = &chain_bytes[0];
    let mut subject_dn = None;
    let mut issuer_dn = None;
    let mut san_uris = Vec::new();
    let mut san_dns = Vec::new();
    let mut san_emails = Vec::new();
    let mut not_before = None;
    let mut not_after = None;
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(leaf_bytes) {
        subject_dn = Some(cert.subject().to_string());
        issuer_dn = Some(cert.issuer().to_string());
        let validity = cert.validity();
        not_before = validity
            .not_before
            .to_datetime()
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
        not_after = validity
            .not_after
            .to_datetime()
            .format(&time::format_description::well_known::Rfc3339)
            .ok();
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for gn in &san.general_names {
                    use x509_parser::extensions::GeneralName;
                    match gn {
                        GeneralName::URI(s) => san_uris.push((*s).to_owned()),
                        GeneralName::DNSName(s) => san_dns.push((*s).to_owned()),
                        GeneralName::RFC822Name(s) => san_emails.push((*s).to_owned()),
                        _ => {}
                    }
                }
            }
        }
    }

    TlsInfo {
        sni,
        client_cert_present: true,
        client_cert_chain_der: chain_bytes,
        client_cert_subject_dn: subject_dn,
        client_cert_issuer_dn: issuer_dn,
        client_cert_san_uris: san_uris,
        client_cert_san_dns: san_dns,
        client_cert_san_emails: san_emails,
        client_cert_chain_sha256: chain_sha256,
        client_cert_not_before: not_before,
        client_cert_not_after: not_after,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };
    use tempfile::NamedTempFile;

    fn make_ca() -> (Vec<u8>, Issuer<'static, KeyPair>) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "Test CA");
            dn
        };
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        (der, Issuer::new(params, key))
    }

    fn make_server_cert_pem(issuer: &Issuer<'static, KeyPair>) -> (String, String) {
        let mut params = CertificateParams::default();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "localhost");
            dn
        };
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write_pem(content: &str) -> NamedTempFile {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), content).unwrap();
        f
    }

    #[test]
    fn build_server_config_no_client_auth() {
        let (_ca, issuer) = make_ca();
        let (cert_pem, key_pem) = make_server_cert_pem(&issuer);
        let cert_file = write_pem(&cert_pem);
        let key_file = write_pem(&key_pem);
        let cfg = TlsConfig {
            cert_path: cert_file.path().to_str().unwrap().into(),
            key_path: key_file.path().to_str().unwrap().into(),
            min_tls_version: "1.2".into(),
            client_ca_certs_path: None,
            client_cert_required: ClientCertMode::None,
        };
        let server_config = build_server_config(&cfg).unwrap();
        assert_eq!(server_config.alpn_protocols.len(), 2);
        assert_eq!(server_config.alpn_protocols[0], b"h2");
    }

    #[test]
    fn build_server_config_with_mandatory_client_auth() {
        let (ca_der, issuer) = make_ca();
        let (cert_pem, key_pem) = make_server_cert_pem(&issuer);
        let cert_file = write_pem(&cert_pem);
        let key_file = write_pem(&key_pem);
        // CA bundle is the same self-signed CA, in PEM form.
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;
        let ca_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(&ca_der)
                .as_bytes()
                .chunks(64)
                .map(std::str::from_utf8)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .join("\n")
        );
        let ca_file = write_pem(&ca_pem);
        let cfg = TlsConfig {
            cert_path: cert_file.path().to_str().unwrap().into(),
            key_path: key_file.path().to_str().unwrap().into(),
            min_tls_version: "1.3".into(),
            client_ca_certs_path: Some(ca_file.path().to_str().unwrap().into()),
            client_cert_required: ClientCertMode::Mandatory,
        };
        // Just verifying it builds without error — actual mTLS
        // handshake exercise happens in the integration test.
        build_server_config(&cfg).unwrap();
    }

    #[test]
    fn tls_protocol_versions_1_3_is_tls13_only() {
        let versions = tls_protocol_versions("1.3").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, rustls::version::TLS13.version);
    }

    #[test]
    fn tls_protocol_versions_1_2_permits_both() {
        let versions = tls_protocol_versions("1.2").unwrap();
        assert_eq!(versions.len(), 2);
        // TLS 1.2 must be present — that's the whole point of the "1.2" floor.
        assert!(
            versions
                .iter()
                .any(|v| v.version == rustls::version::TLS12.version)
        );
        assert!(
            versions
                .iter()
                .any(|v| v.version == rustls::version::TLS13.version)
        );
    }

    #[test]
    fn tls_protocol_versions_tolerates_surrounding_whitespace() {
        assert_eq!(tls_protocol_versions("  1.3 ").unwrap().len(), 1);
    }

    #[test]
    fn tls_protocol_versions_rejects_unknown() {
        assert!(tls_protocol_versions("1.1").is_err());
        assert!(tls_protocol_versions("tls1.3").is_err());
        assert!(tls_protocol_versions("").is_err());
    }

    #[test]
    fn build_server_config_accepts_min_tls_1_3() {
        let (_ca, issuer) = make_ca();
        let (cert_pem, key_pem) = make_server_cert_pem(&issuer);
        let cert_file = write_pem(&cert_pem);
        let key_file = write_pem(&key_pem);
        let cfg = TlsConfig {
            cert_path: cert_file.path().to_str().unwrap().into(),
            key_path: key_file.path().to_str().unwrap().into(),
            min_tls_version: "1.3".into(),
            client_ca_certs_path: None,
            client_cert_required: ClientCertMode::None,
        };
        // The rustls ServerConfig is built from the protocol-version set, so a
        // successful build with min "1.3" confirms the version floor is applied.
        build_server_config(&cfg).unwrap();
    }

    #[test]
    fn tls_info_from_empty_chain() {
        let info = tls_info_from_chain(Some("api.example.com".into()), vec![]);
        assert_eq!(info.sni.as_deref(), Some("api.example.com"));
        assert!(!info.client_cert_present);
        assert!(info.client_cert_chain_der.is_empty());
        assert!(info.client_cert_subject_dn.is_none());
    }

    #[test]
    fn tls_info_extracts_subject_san_validity() {
        let (_ca, issuer) = make_ca();
        // Leaf with a SPIFFE URI SAN + DNS SAN.
        let mut leaf_params = CertificateParams::default();
        leaf_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "test-workload");
            dn
        };
        leaf_params.subject_alt_names = vec![
            SanType::URI(
                "spiffe://example.org/ns/payments/sa/orders"
                    .try_into()
                    .unwrap(),
            ),
            SanType::DnsName("orders.payments.svc".try_into().unwrap()),
        ];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let leaf_der = leaf_cert.der().to_vec();
        let chain: Vec<CertificateDer<'static>> = vec![CertificateDer::from(leaf_der.clone())];

        let info = tls_info_from_chain(Some("orders".into()), chain);
        assert_eq!(info.sni.as_deref(), Some("orders"));
        assert!(info.client_cert_present);
        assert_eq!(info.client_cert_chain_der.len(), 1);
        assert_eq!(
            info.client_cert_chain_der[0], leaf_der,
            "chain DER round-trips losslessly"
        );
        assert_eq!(info.client_cert_chain_sha256.len(), 1);
        assert_eq!(info.client_cert_chain_sha256[0].len(), 64); // hex sha256
        let subject = info.client_cert_subject_dn.as_deref().unwrap_or("");
        assert!(subject.contains("CN=test-workload"), "got: {subject}");
        let issuer_dn = info.client_cert_issuer_dn.as_deref().unwrap_or("");
        assert!(issuer_dn.contains("CN=Test CA"), "got: {issuer_dn}");
        assert_eq!(info.client_cert_san_uris.len(), 1);
        assert_eq!(
            info.client_cert_san_uris[0],
            "spiffe://example.org/ns/payments/sa/orders"
        );
        assert_eq!(info.client_cert_san_dns.len(), 1);
        assert_eq!(info.client_cert_san_dns[0], "orders.payments.svc");
        assert!(info.client_cert_san_emails.is_empty());
        // Validity bounds parse as RFC3339.
        let nb = info.client_cert_not_before.as_deref().unwrap_or("");
        assert!(
            chrono::DateTime::parse_from_rfc3339(nb).is_ok(),
            "not_before is RFC3339: {nb}"
        );
    }

    #[test]
    fn tls_info_handles_unparseable_leaf() {
        // Garbage bytes for the leaf — the helper falls through to
        // an info with the chain populated but DN/SAN absent.
        let chain = vec![CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef])];
        let info = tls_info_from_chain(None, chain);
        assert!(info.client_cert_present);
        assert_eq!(info.client_cert_chain_der.len(), 1);
        assert!(info.client_cert_subject_dn.is_none());
        assert!(info.client_cert_san_uris.is_empty());
    }

    /// `InjectTlsInfo` is the per-connection tower middleware that
    /// stamps the parsed `TlsInfo` onto every `axum::http::Request`
    /// passing through. It runs before any axum extractor, so the
    /// HTTP handlers see the extension via
    /// `req.extensions().get::<TlsInfoArc>()`.
    #[tokio::test]
    async fn inject_tls_info_stamps_extension_on_every_request() {
        use axum::http::Request;

        // Stub service: records the TlsInfoArc it observed (or
        // None) and echoes a unit response.
        struct Recorder(Arc<std::sync::Mutex<Option<TlsInfoArc>>>);
        impl<B> Service<Request<B>> for Recorder {
            type Response = ();
            type Error = std::convert::Infallible;
            type Future = std::pin::Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;
            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn call(&mut self, req: Request<B>) -> Self::Future {
                let observed = req.extensions().get::<TlsInfoArc>().cloned();
                let slot = self.0.clone();
                Box::pin(async move {
                    *slot.lock().unwrap() = observed;
                    Ok(())
                })
            }
        }

        let observed = Arc::new(std::sync::Mutex::new(None));
        let info = Arc::new(tls_info_from_chain(Some("api.example.com".into()), vec![]));
        let mut svc = InjectTlsInfo {
            inner: Recorder(observed.clone()),
            tls_info: Some(info.clone()),
            peer: None,
        };
        let req: Request<()> = Request::builder().body(()).unwrap();
        svc.call(req).await.unwrap();
        let stamped = observed.lock().unwrap().clone().expect("extension present");
        assert!(Arc::ptr_eq(&stamped, &info));
    }

    #[tokio::test]
    async fn inject_tls_info_omits_extension_when_acceptor_returned_none() {
        use axum::http::Request;

        struct Recorder(Arc<std::sync::Mutex<Option<TlsInfoArc>>>);
        impl<B> Service<Request<B>> for Recorder {
            type Response = ();
            type Error = std::convert::Infallible;
            type Future = std::pin::Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;
            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn call(&mut self, req: Request<B>) -> Self::Future {
                let observed = req.extensions().get::<TlsInfoArc>().cloned();
                let slot = self.0.clone();
                Box::pin(async move {
                    *slot.lock().unwrap() = observed;
                    Ok(())
                })
            }
        }

        let observed = Arc::new(std::sync::Mutex::new(None));
        let mut svc = InjectTlsInfo {
            inner: Recorder(observed.clone()),
            tls_info: None,
            peer: None,
        };
        let req: Request<()> = Request::builder().body(()).unwrap();
        svc.call(req).await.unwrap();
        assert!(observed.lock().unwrap().is_none());
    }
}
