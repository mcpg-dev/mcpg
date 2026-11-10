//! The gateway's HTTP server for `http`-wire transport plugins.
//!
//! A plugin such as `dev.mcpg.transport.ngrok` owns the connections and
//! hands the gateway whole HTTP requests. Each one runs through the same
//! router the gateway's own listener serves, so identity, OAuth discovery,
//! per-IP rate limits, SSE and both MCP revisions behave the same.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use bytes::Bytes;
use futures::StreamExt as _;
use mcpg_plugin_protocol::transport::{
    HttpIngressRequestHead, HttpIngressResponse, HttpIngressResponseHead, HttpIngressServer,
};
use tower::ServiceExt as _;

use crate::transports::attested::{AttestedPeer, AttestedPeerArc};
use crate::transports::tls::TlsInfoArc;

/// The largest request body an `http`-wire transport may hand over. MCP
/// request bodies are small JSON documents.
pub const MAX_INGRESS_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The client address recorded when a transport reports none. Such
/// clients share one per-IP rate-limit bucket instead of skipping the
/// limit.
const UNKNOWN_CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Serves one `http`-wire transport's requests through the gateway router.
pub struct GatewayHttpIngress {
    router: Router,
    /// The transport's plugin id; a peer it attests is recorded under it.
    transport: String,
}

impl GatewayHttpIngress {
    #[must_use]
    pub fn new(router: Router, transport: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            router,
            transport: transport.into(),
        })
    }
}

#[mcpg_plugin_protocol::async_trait]
impl HttpIngressServer for GatewayHttpIngress {
    async fn serve(&self, head: HttpIngressRequestHead, body: Bytes) -> HttpIngressResponse {
        if body.len() > MAX_INGRESS_BODY_BYTES {
            return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
        let request = match build_request(head, body, &self.transport) {
            Ok(request) => request,
            Err(reason) => return plain(StatusCode::BAD_REQUEST, &reason),
        };
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .unwrap_or_else(|e: Infallible| match e {});
        let (parts, body) = response.into_parts();
        let headers = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        HttpIngressResponse {
            head: HttpIngressResponseHead {
                status: parts.status.as_u16(),
                headers,
            },
            body: Box::pin(
                body.into_data_stream()
                    .map(|frame| frame.map_err(|e| e.to_string())),
            ),
        }
    }
}

fn build_request(
    head: HttpIngressRequestHead,
    body: Bytes,
    transport: &str,
) -> Result<Request<Body>, String> {
    let method = Method::from_bytes(head.method.as_bytes())
        .map_err(|_| format!("invalid method {:?}", head.method))?;
    if !head.uri.starts_with('/') {
        return Err(format!("the request target {:?} is not a path", head.uri));
    }
    let mut builder = Request::builder().method(method).uri(head.uri.as_str());
    for (name, value) in &head.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| format!("invalid header name {name:?}"))?;
        let value =
            HeaderValue::from_str(value).map_err(|_| format!("invalid value for header {name}"))?;
        builder = builder.header(name, value);
    }
    let mut request = builder.body(Body::from(body)).map_err(|e| e.to_string())?;
    let client = head
        .remote_addr
        .as_deref()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
        .unwrap_or(UNKNOWN_CLIENT);
    request.extensions_mut().insert(ConnectInfo(client));
    if let Some(tls) = head.tls {
        request.extensions_mut().insert::<TlsInfoArc>(Arc::new(tls));
    }
    if let Some(peer) = head.peer {
        request
            .extensions_mut()
            .insert::<AttestedPeerArc>(Arc::new(AttestedPeer {
                transport: transport.to_owned(),
                peer,
            }));
    }
    Ok(request)
}

fn plain(status: StatusCode, message: &str) -> HttpIngressResponse {
    HttpIngressResponse {
        head: HttpIngressResponseHead {
            status: status.as_u16(),
            headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
        },
        body: Box::pin(futures::stream::iter([Ok(Bytes::from(message.to_owned()))])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use axum::response::sse::{Event, Sse};
    use axum::routing::{get, post};

    fn router() -> Router {
        Router::new()
            .route(
                "/echo",
                post(
                    |ConnectInfo(addr): ConnectInfo<SocketAddr>,
                     headers: HeaderMap,
                     tls: Option<axum::Extension<TlsInfoArc>>,
                     body: Bytes| async move {
                        let host = headers
                            .get("host")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let sni = tls.and_then(|t| t.0.sni.clone()).unwrap_or_default();
                        (
                            [
                                ("x-client", addr.to_string()),
                                ("x-host", host),
                                ("x-sni", sni),
                            ],
                            body,
                        )
                    },
                ),
            )
            .route(
                "/peer",
                get(
                    |peer: Option<axum::Extension<AttestedPeerArc>>| async move {
                        peer.map(|p| format!("{} {}", p.0.transport, p.0.peer.subject_id))
                            .unwrap_or_default()
                    },
                ),
            )
            .route(
                "/sse",
                get(|| async {
                    let events = futures::stream::iter(["a", "b"])
                        .map(|d| Ok::<_, Infallible>(Event::default().data(d)));
                    Sse::new(events)
                }),
            )
    }

    async fn collect(response: HttpIngressResponse) -> (HttpIngressResponseHead, Vec<u8>) {
        let mut body = Vec::new();
        let mut frames = response.body;
        while let Some(frame) = frames.next().await {
            body.extend_from_slice(&frame.unwrap());
        }
        (response.head, body)
    }

    fn header<'a>(head: &'a HttpIngressResponseHead, name: &str) -> Option<&'a str> {
        head.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn a_request_reaches_the_router_with_the_client_address_host_and_tls() {
        let server = GatewayHttpIngress::new(router(), "dev.test.transport");
        let head = HttpIngressRequestHead {
            method: "POST".into(),
            uri: "/echo".into(),
            headers: vec![("host".into(), "x.ngrok.app".into())],
            remote_addr: Some("203.0.113.7:4242".into()),
            tls: Some(mcpg_plugin_protocol::types::TlsInfo {
                sni: Some("x.ngrok.app".into()),
                ..Default::default()
            }),
            peer: None,
        };
        let (head, body) = collect(server.serve(head, Bytes::from_static(b"ping")).await).await;
        assert_eq!(head.status, 200);
        assert_eq!(header(&head, "x-client"), Some("203.0.113.7:4242"));
        assert_eq!(header(&head, "x-host"), Some("x.ngrok.app"));
        assert_eq!(header(&head, "x-sni"), Some("x.ngrok.app"));
        assert_eq!(body, b"ping");
    }

    #[tokio::test]
    async fn a_client_without_an_address_gets_the_shared_unknown_address() {
        let server = GatewayHttpIngress::new(router(), "dev.test.transport");
        let head = HttpIngressRequestHead {
            method: "POST".into(),
            uri: "/echo".into(),
            ..Default::default()
        };
        let (head, _) = collect(server.serve(head, Bytes::new()).await).await;
        assert_eq!(header(&head, "x-client"), Some("0.0.0.0:0"));
    }

    #[tokio::test]
    async fn an_attested_peer_reaches_the_router_under_the_transport_that_serves_it() {
        let server = GatewayHttpIngress::new(router(), "dev.mcpg.transport.tailscale");
        let head = HttpIngressRequestHead {
            method: "GET".into(),
            uri: "/peer".into(),
            peer: Some(mcpg_plugin_protocol::transport::TransportPeer {
                provider: "tailscale".into(),
                trust_level: "verified".into(),
                subject_id: "alice@example.com".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (_, body) = collect(server.serve(head, Bytes::new()).await).await;
        assert_eq!(body, b"dev.mcpg.transport.tailscale alice@example.com");
        let plain = HttpIngressRequestHead {
            method: "GET".into(),
            uri: "/peer".into(),
            ..Default::default()
        };
        let (_, body) = collect(server.serve(plain, Bytes::new()).await).await;
        assert!(body.is_empty(), "no peer, no extension");
    }

    #[tokio::test]
    async fn an_sse_answer_streams_its_events() {
        let server = GatewayHttpIngress::new(router(), "dev.test.transport");
        let head = HttpIngressRequestHead {
            method: "GET".into(),
            uri: "/sse".into(),
            ..Default::default()
        };
        let (head, body) = collect(server.serve(head, Bytes::new()).await).await;
        assert_eq!(header(&head, "content-type"), Some("text/event-stream"));
        assert_eq!(String::from_utf8(body).unwrap(), "data: a\n\ndata: b\n\n");
    }

    #[tokio::test]
    async fn bad_requests_and_oversized_bodies_are_refused_before_the_router() {
        let server = GatewayHttpIngress::new(router(), "dev.test.transport");
        for head in [
            HttpIngressRequestHead {
                method: "PO ST".into(),
                uri: "/echo".into(),
                ..Default::default()
            },
            HttpIngressRequestHead {
                method: "POST".into(),
                uri: "https://elsewhere.example/echo".into(),
                ..Default::default()
            },
            HttpIngressRequestHead {
                method: "POST".into(),
                uri: "/echo".into(),
                headers: vec![("bad header".into(), "x".into())],
                ..Default::default()
            },
        ] {
            let (head, _) = collect(server.serve(head, Bytes::new()).await).await;
            assert_eq!(head.status, 400);
        }
        let big = Bytes::from(vec![b'x'; MAX_INGRESS_BODY_BYTES + 1]);
        let head = HttpIngressRequestHead {
            method: "POST".into(),
            uri: "/echo".into(),
            ..Default::default()
        };
        let (head, _) = collect(server.serve(head, big).await).await;
        assert_eq!(head.status, 413);
    }
}
