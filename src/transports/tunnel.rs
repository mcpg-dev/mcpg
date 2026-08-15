//! `mcpg --tunnel`: dial an MCPG-Cloud relay and answer tunnelled MCP traffic
//! through the gateway's own router, with no local TCP bind.
//!
//! This module owns the gateway-specific glue: mapping the config
//! ([`TunnelConfig`]) to the wire spec, and the request decorator that turns
//! the relay-attested TLS metadata into the gateway's own [`TlsInfo`] so mTLS
//! identity plugins work. The transport-agnostic accept/`oneshot` engine lives
//! in `mcpg-tunnel-agent`; the concrete relay dial lives in the boot path.

use std::sync::Arc;

use axum::Router;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use mcpg_plugin_protocol::types::TlsInfo;
use mcpg_tunnel_agent::RequestDecorator;
use mcpg_tunnel_proto::{AgentSession, Exposure, HandshakeRequest, TrustMode, TunnelSpec};

use crate::config::{TunnelConfig, TunnelExposure, TunnelTrustMode};
use crate::transports::tls::TlsInfoArc;

/// The request decorator the tunnel agent applies to every replayed request:
/// map the relay-attested TLS metadata onto the gateway's own `TlsInfo`
/// extension so mTLS identity plugins see the client cert. `ConnectInfo` (the
/// rate-limit input) is already injected by the agent before this runs.
pub fn gateway_decorator() -> RequestDecorator {
    Arc::new(|req, attested| {
        let Some(tls) = &attested.tls else {
            return;
        };
        let info = TlsInfo {
            sni: tls.sni.clone(),
            client_cert_present: tls.client_cert_present,
            client_cert_san_uris: tls.san_uris.clone(),
            // The relay attests the chain digest(s); the full DER chain is not
            // ferried, so DN / DER fields stay at their defaults.
            client_cert_chain_sha256: tls.client_cert_chain_sha256.clone().into_iter().collect(),
            ..Default::default()
        };
        req.extensions_mut().insert::<TlsInfoArc>(Arc::new(info));
    })
}

fn to_spec(cfg: &TunnelConfig) -> TunnelSpec {
    TunnelSpec {
        name: cfg.name.clone(),
        exposure: match cfg.exposure {
            TunnelExposure::Public => Exposure::Public,
            TunnelExposure::Private => Exposure::Private,
        },
        mode: match cfg.mode {
            TunnelTrustMode::RelayTerminated => TrustMode::RelayTerminated,
            TunnelTrustMode::E2ee => TrustMode::E2ee,
        },
    }
}

/// Establish a tunnel over an already-connected `transport` (a TLS WebSocket
/// in production, an in-memory duplex in tests), complete the handshake
/// (presenting `bearer` as the dial-in credential the relay authenticates),
/// and serve `router` through it until the relay hangs up.
pub async fn serve_over<T>(
    transport: T,
    router: Router,
    cfg: &TunnelConfig,
    instance_uid: impl Into<String>,
    bearer: Option<String>,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut req = HandshakeRequest::new(instance_uid, to_spec(cfg));
    req.bearer = bearer;
    let (session, resp) = AgentSession::connect(transport, req).await?;
    match &resp.public_url {
        Some(url) => {
            tracing::info!(tunnel_id = %resp.tunnel_id, url = %url, "tunnel established (public)");
        }
        None => {
            tracing::info!(tunnel_id = %resp.tunnel_id, "tunnel established (private)");
        }
    }
    mcpg_tunnel_agent::serve(session, router, gateway_decorator()).await?;
    Ok(())
}

/// Boot the tunnel as the gateway's transport: build the gateway router, dial
/// the MCPG-Cloud relay, and answer tunnelled MCP traffic through the gateway's
/// own request path — with NO public TCP bind. Reconnects with capped backoff
/// until `shutdown` fires; the router is rebuilt on each dial so a hot config
/// reload is picked up on the next reconnect.
pub async fn run(
    state: crate::app::AppState,
    cfg: TunnelConfig,
    shutdown: tokio::sync::watch::Receiver<()>,
) -> anyhow::Result<()> {
    let (health_path, mcp_path) = {
        let c = state.config.load();
        (
            c.gateway.server.health_path.clone(),
            c.gateway.server.mcp_path.clone(),
        )
    };
    let bearer = tunnel_bearer();
    let tls = if relay_is_tls(&cfg.relay_url) {
        Some(tls_connector()?)
    } else {
        None
    };
    let make_router =
        move || crate::transports::http::router(state.clone(), &health_path, &mcp_path);
    run_loop(cfg, make_router, bearer, tls, shutdown).await
}

/// The bearer credential the gateway presents to the relay, read from
/// `MCPG_TUNNEL_TOKEN` (kept out of the serializable config so it never lands
/// in the config digest, a `mcpg config` dump, or a reload diff). A CP-attached
/// gateway's instance JWT is a follow-on source. When unset, only an
/// unauthenticated / dev relay will accept the dial-in.
fn tunnel_bearer() -> Option<String> {
    std::env::var("MCPG_TUNNEL_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
}

/// The dial → serve → reconnect loop, split from [`run`] so it is testable
/// without standing up a full `AppState` (a test drives it with a trivial
/// router over a loopback relay).
async fn run_loop<F>(
    cfg: TunnelConfig,
    mut make_router: F,
    bearer: Option<String>,
    tls: Option<TlsConnector>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
) -> anyhow::Result<()>
where
    F: FnMut() -> Router,
{
    let authority = relay_authority(&cfg.relay_url)?;
    let instance_uid = instance_uid();
    let server_name = match &tls {
        Some(_) => Some(relay_server_name(&authority)?),
        None => None,
    };
    tracing::info!(
        relay = %authority,
        tls = tls.is_some(),
        exposure = ?cfg.exposure,
        mode = ?cfg.mode,
        "tunnel transport: dialing relay (no public bind)"
    );

    let base_backoff = std::time::Duration::from_millis(500);
    let backoff_cap = std::time::Duration::from_secs(30);
    let mut backoff = base_backoff;
    loop {
        // Rebuild per dial so a config reload lands on the next reconnect.
        let router = make_router();
        let attempt = async {
            let tcp = tokio::net::TcpStream::connect(&authority).await?;
            let _ = tcp.set_nodelay(true);
            // TLS-wrap the tunnel dial when the relay speaks it; `serve_over` is
            // generic over the stream, so both branches share the code below.
            match (&tls, &server_name) {
                (Some(connector), Some(name)) => {
                    let stream = connector.connect(name.clone(), tcp).await?;
                    serve_over(stream, router, &cfg, instance_uid.clone(), bearer.clone()).await
                }
                _ => serve_over(tcp, router, &cfg, instance_uid.clone(), bearer.clone()).await,
            }
        };
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("tunnel transport: shutdown signal received");
                return Ok(());
            }
            res = attempt => match res {
                Ok(()) => {
                    tracing::info!("tunnel closed by relay; reconnecting");
                    backoff = base_backoff;
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    backoff_ms = backoff.as_millis() as u64,
                    "tunnel dial/serve failed; retrying"
                ),
            }
        }
        // Pause before redial, but wake immediately on shutdown.
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(backoff_cap);
    }
}

/// Resolve the `host:port` to dial from a relay URL. Accepts `wss://`, `ws://`,
/// `tcp://`, or a bare authority; a missing port defaults to 443 (the relay
/// fronts TLS on 443 in production — the MVP dials that authority over plain
/// TCP, WSS wrapping is a follow-on hardening layer).
fn relay_authority(relay_url: &str) -> anyhow::Result<String> {
    let rest = relay_url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(relay_url);
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    if authority.is_empty() {
        anyhow::bail!("server.tunnel.relay_url has no host: {relay_url:?}");
    }
    // A bracketed IPv6 host (`[::1]:443`) or `host:port` already carries a port.
    let has_port = match authority.rfind(']') {
        Some(close) => authority[close..].contains(':'),
        None => authority.contains(':'),
    };
    Ok(if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:443")
    })
}

/// Whether the relay URL asks for TLS on the dial (`wss`/`tls`/`https`). A
/// `tcp://` or bare authority dials plaintext.
fn relay_is_tls(relay_url: &str) -> bool {
    matches!(
        relay_url.split_once("://").map(|(s, _)| s),
        Some("wss" | "tls" | "https")
    )
}

/// Build the outbound TLS client connector for the relay dial. Trust anchors are
/// the Mozilla webpki roots plus, when `MCPG_TUNNEL_CA` is set, a private CA
/// (PEM) for a self-hosted relay.
fn tls_connector() -> anyhow::Result<TlsConnector> {
    crate::transports::tls::install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(ca_path) = std::env::var("MCPG_TUNNEL_CA") {
        let data = std::fs::read(&ca_path)
            .map_err(|e| anyhow::anyhow!("read MCPG_TUNNEL_CA {ca_path}: {e}"))?;
        let mut reader = std::io::BufReader::new(&data[..]);
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert?)?;
        }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The SNI / verification name for the relay dial — the authority host without
/// its port (bracketed IPv6 is unwrapped to its literal).
fn relay_server_name(authority: &str) -> anyhow::Result<rustls_pki_types::ServerName<'static>> {
    let host = match authority.rfind(']') {
        Some(close) => authority[..=close]
            .trim_start_matches('[')
            .trim_end_matches(']'),
        None => authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority),
    };
    rustls_pki_types::ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid relay host {host:?}: {e}"))
}

/// This gateway instance's tunnel identity — the relay keys an unnamed tunnel
/// by it. Mirrors the CP-attach instance-uid shape (`{host}-{uuid8}`).
fn instance_uid() -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_else(|| "mcpg".to_owned());
    format!("{host}-{}", &uuid::Uuid::now_v7().to_string()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use mcpg_tunnel_proto::{
        AttestedMeta, Frame, HandshakeResponse, RelaySession, RequestHead, TlsMeta,
    };

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            enabled: true,
            relay_url: "wss://relay.test".to_owned(),
            name: Some("acme".to_owned()),
            exposure: TunnelExposure::Private,
            mode: TunnelTrustMode::RelayTerminated,
        }
    }

    // Reflects the TlsInfo the decorator injected, proving attested TLS reaches
    // the gateway's request path.
    fn tls_router() -> Router {
        Router::new().route(
            "/tls",
            get(|req: axum::extract::Request| async move {
                match req.extensions().get::<TlsInfoArc>() {
                    Some(info) => format!(
                        "sni={};cert={};san={}",
                        info.sni.clone().unwrap_or_default(),
                        info.client_cert_present,
                        info.client_cert_san_uris.join(",")
                    ),
                    None => "no-tls".to_owned(),
                }
            }),
        )
    }

    #[tokio::test]
    async fn serve_over_injects_attested_tls_into_the_router() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let config = cfg();

        // Both handshake halves must run concurrently (see mcpg-tunnel-agent).
        let (relay, _serve) = tokio::join!(
            async {
                RelaySession::accept(server_io, async |req| {
                    Ok::<_, mcpg_tunnel_proto::ProtoError>(HandshakeResponse {
                        accepted_proto_version: req.proto_version.clone(),
                        tunnel_id: "acme-1".to_owned(),
                        public_url: None,
                        heartbeat_secs: 30,
                    })
                })
                .await
                .unwrap()
            },
            async {
                tokio::spawn(async move {
                    let _ = serve_over(client_io, tls_router(), &config, "inst-1", None).await;
                });
            },
        );
        let (relay, _req) = relay;

        // Send a request carrying attested TLS; expect the handler to echo it.
        let mut s = relay.open_request().await.unwrap();
        s.send(Frame::RequestHead(RequestHead {
            method: "GET".to_owned(),
            path: "/tls".to_owned(),
            query: None,
            headers: vec![],
            attested: AttestedMeta {
                client_ip: None,
                tls: Some(TlsMeta {
                    sni: Some("acme.tunnels.mcpg.cloud".to_owned()),
                    client_cert_present: true,
                    client_cert_chain_sha256: Some("deadbeef".to_owned()),
                    san_uris: vec!["spiffe://mcpg/instance/inst-1".to_owned()],
                }),
            },
        }))
        .await
        .unwrap();
        s.send(Frame::BodyEnd).await.unwrap();

        let status = match s.recv().await.unwrap().unwrap() {
            Frame::ResponseHead(h) => h.status,
            other => panic!("expected ResponseHead, got {other:?}"),
        };
        assert_eq!(status, 200);
        let mut body = Vec::new();
        loop {
            match s.recv().await.unwrap() {
                Some(Frame::BodyChunk(b)) => body.extend_from_slice(&b),
                Some(Frame::BodyEnd) | None => break,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        let text = String::from_utf8(body).unwrap();
        assert_eq!(
            text,
            "sni=acme.tunnels.mcpg.cloud;cert=true;san=spiffe://mcpg/instance/inst-1"
        );
    }

    /// The gateway presents its dial-in credential as the handshake bearer so
    /// an authenticating relay can verify it.
    #[tokio::test]
    async fn serve_over_presents_the_bearer_to_the_relay() {
        use std::sync::{Arc, Mutex};
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let config = cfg();
        let seen: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
        let captured = seen.clone();

        let (relay, _serve) = tokio::join!(
            async move {
                RelaySession::accept(server_io, async move |req| {
                    *captured.lock().unwrap() = Some(req.bearer.clone());
                    Ok::<_, mcpg_tunnel_proto::ProtoError>(HandshakeResponse {
                        accepted_proto_version: req.proto_version.clone(),
                        tunnel_id: "acme-1".to_owned(),
                        public_url: None,
                        heartbeat_secs: 30,
                    })
                })
                .await
                .unwrap()
            },
            async {
                tokio::spawn(async move {
                    let _ = serve_over(
                        client_io,
                        Router::new(),
                        &config,
                        "inst-1",
                        Some("s3cret".to_owned()),
                    )
                    .await;
                });
            },
        );
        let _ = relay;
        assert_eq!(
            seen.lock().unwrap().clone(),
            Some(Some("s3cret".to_owned()))
        );
    }

    /// The boot loop dials a *real* TCP relay, completes the handshake, and
    /// answers one request through the served router — proving the dial glue
    /// over a socket (not just an in-memory duplex).
    #[tokio::test]
    async fn run_loop_dials_a_real_tcp_relay_and_serves_a_request() {
        use axum::routing::post;
        use bytes::Bytes;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut config = cfg();
        config.relay_url = format!("tcp://{addr}");

        let (tx, rx) = tokio::sync::watch::channel(());
        let loop_task = tokio::spawn(async move {
            let make = || {
                Router::new().route(
                    "/mcp",
                    post(|body: String| async move { format!("echo:{body}") }),
                )
            };
            run_loop(config, make, None, None, rx).await
        });

        // Relay side: accept the dialed agent and answer a single request.
        let (sock, _) = listener.accept().await.unwrap();
        let (relay, _req) = RelaySession::accept(sock, async |req| {
            Ok::<_, mcpg_tunnel_proto::ProtoError>(HandshakeResponse {
                accepted_proto_version: req.proto_version.clone(),
                tunnel_id: "t1".to_owned(),
                public_url: None,
                heartbeat_secs: 30,
            })
        })
        .await
        .unwrap();

        let mut s = relay.open_request().await.unwrap();
        s.send(Frame::RequestHead(RequestHead {
            method: "POST".to_owned(),
            path: "/mcp".to_owned(),
            query: None,
            headers: vec![],
            attested: AttestedMeta::default(),
        }))
        .await
        .unwrap();
        s.send(Frame::BodyChunk(Bytes::from_static(b"hi")))
            .await
            .unwrap();
        s.send(Frame::BodyEnd).await.unwrap();

        let status = match s.recv().await.unwrap().unwrap() {
            Frame::ResponseHead(h) => h.status,
            other => panic!("expected ResponseHead, got {other:?}"),
        };
        assert_eq!(status, 200);
        let mut body = Vec::new();
        while let Some(Frame::BodyChunk(b)) = s.recv().await.unwrap() {
            body.extend_from_slice(&b);
        }
        assert_eq!(String::from_utf8(body).unwrap(), "echo:hi");

        // Stop the reconnect loop and confirm it exits cleanly.
        tx.send(()).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[test]
    fn relay_authority_resolves_scheme_and_default_port() {
        assert_eq!(
            relay_authority("wss://relay.mcpg.cloud").unwrap(),
            "relay.mcpg.cloud:443"
        );
        assert_eq!(
            relay_authority("wss://relay.mcpg.cloud:8443/x").unwrap(),
            "relay.mcpg.cloud:8443"
        );
        assert_eq!(
            relay_authority("tcp://127.0.0.1:7000").unwrap(),
            "127.0.0.1:7000"
        );
        assert_eq!(
            relay_authority("relay.mcpg.cloud").unwrap(),
            "relay.mcpg.cloud:443"
        );
        assert_eq!(relay_authority("[::1]:9000").unwrap(), "[::1]:9000");
        assert_eq!(
            relay_authority("[2001:db8::1]").unwrap(),
            "[2001:db8::1]:443"
        );
        assert!(relay_authority("wss://").is_err());
    }

    #[test]
    fn relay_is_tls_keys_on_scheme() {
        assert!(relay_is_tls("wss://relay.mcpg.cloud"));
        assert!(relay_is_tls("tls://relay:8443"));
        assert!(relay_is_tls("https://relay"));
        assert!(!relay_is_tls("tcp://127.0.0.1:7000"));
        assert!(!relay_is_tls("relay.mcpg.cloud:443"));
    }

    #[test]
    fn relay_server_name_strips_the_port() {
        assert_eq!(
            relay_server_name("relay.mcpg.cloud:443").unwrap(),
            rustls_pki_types::ServerName::try_from("relay.mcpg.cloud").unwrap()
        );
        assert!(relay_server_name("127.0.0.1:8443").is_ok());
        assert!(relay_server_name("[2001:db8::1]:443").is_ok());
    }

    /// The boot loop TLS-dials a relay over a real socket and round-trips one
    /// request through the encrypted tunnel.
    #[tokio::test]
    async fn run_loop_dials_a_relay_over_tls() {
        use axum::routing::post;
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};
        use std::net::{IpAddr, Ipv4Addr};

        crate::transports::tls::install_default_crypto_provider();

        // Self-signed cert with an IP SAN so verification needs no DNS.
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().unwrap()),
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ];
        let cert = params.self_signed(&key).unwrap();
        let cert_der = cert.der().clone();
        let key_der = rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let (tx, rx) = tokio::sync::watch::channel(());
        let mut config = cfg();
        config.relay_url = format!("tls://{addr}");
        let loop_task = tokio::spawn(async move {
            let make = || {
                Router::new().route(
                    "/mcp",
                    post(|body: String| async move { format!("echo:{body}") }),
                )
            };
            run_loop(config, make, None, Some(connector), rx).await
        });

        let (sock, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(sock).await.unwrap();
        let (relay, _req) = RelaySession::accept(tls, async |req| {
            Ok::<_, mcpg_tunnel_proto::ProtoError>(HandshakeResponse {
                accepted_proto_version: req.proto_version.clone(),
                tunnel_id: "t1".to_owned(),
                public_url: None,
                heartbeat_secs: 30,
            })
        })
        .await
        .unwrap();

        let mut s = relay.open_request().await.unwrap();
        s.send(Frame::RequestHead(RequestHead {
            method: "POST".to_owned(),
            path: "/mcp".to_owned(),
            query: None,
            headers: vec![],
            attested: AttestedMeta::default(),
        }))
        .await
        .unwrap();
        s.send(Frame::BodyChunk(bytes::Bytes::from_static(b"hi")))
            .await
            .unwrap();
        s.send(Frame::BodyEnd).await.unwrap();

        let status = match s.recv().await.unwrap().unwrap() {
            Frame::ResponseHead(h) => h.status,
            other => panic!("expected ResponseHead, got {other:?}"),
        };
        assert_eq!(status, 200);
        let mut body = Vec::new();
        while let Some(Frame::BodyChunk(b)) = s.recv().await.unwrap() {
            body.extend_from_slice(&b);
        }
        assert_eq!(String::from_utf8(body).unwrap(), "echo:hi");

        tx.send(()).unwrap();
        loop_task.await.unwrap().unwrap();
    }
}
