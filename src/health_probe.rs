//! `mcpg --health-check`: one GET against the health endpoint of the gateway
//! that already runs on this host, for an image `HEALTHCHECK`.
//!
//! The probe resolves the config from its own argv and environment the way
//! the gateway does (`--config`, else `MCPG_CONFIG`, then the `MCPG_*`
//! overlay; `--tunnel` and `--stdio` as well) and nothing more: no plugins, no
//! gateway runtime, a single-threaded async runtime for the one request. An
//! image `HEALTHCHECK` passes no arguments, so there it sees only the
//! environment. It covers the plain-HTTP listener; a TLS listener, a tunnel
//! or stdio fails with the reason.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Context as _;

use crate::config::{AppConfig, ServerConfig, TransportMode};

/// Budget for the one GET. Below the image `HEALTHCHECK --timeout` (5 s), so a
/// hung listener reports its own reason rather than being killed.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The address a client on this host dials to reach a listener bound at
/// `bind`. A wildcard bind is reached on the loopback address of its family;
/// any other address, or a host name, is dialled as written.
pub fn local_authority(bind: &str) -> String {
    match bind.parse::<SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => {
            let loopback = match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            };
            SocketAddr::new(loopback, addr.port()).to_string()
        }
        _ => bind.to_owned(),
    }
}

/// The gateway's own health endpoint, as a client on this host reaches it.
pub fn local_health_url(server: &ServerConfig) -> String {
    let scheme = if server.tls.is_some() {
        "https"
    } else {
        "http"
    };
    format!(
        "{scheme}://{}{}",
        local_authority(&server.bind_address),
        server.health_path
    )
}

/// The URL `--health-check` probes, or why this listener cannot be probed.
pub fn probe_url(server: &ServerConfig) -> anyhow::Result<String> {
    if server.transport == TransportMode::Stdio {
        anyhow::bail!("gateway.server.transport is stdio, so there is no HTTP listener to probe");
    }
    if server.tunnel.as_ref().is_some_and(|t| t.enabled) {
        anyhow::bail!(
            "gateway.server.tunnel is enabled, so the gateway serves through the relay and \
             binds no local listener to probe"
        );
    }
    if server.tls.is_some() {
        anyhow::bail!(
            "gateway.server.tls is set and --health-check probes plain HTTP only; \
             probe {} with a client that trusts the gateway certificate",
            local_health_url(server)
        );
    }
    Ok(local_health_url(server))
}

/// One GET to `url`. `Ok` carries the result line for a 2xx; any other
/// status, a refused connection or the timeout is an error.
pub async fn probe(url: &str, timeout: Duration) -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        // A loopback probe must not leave the host through `HTTP_PROXY`, and a
        // redirect is not a healthy answer.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("cannot build the HTTP client")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    anyhow::ensure!(status.is_success(), "GET {url} returned {status}");
    Ok(format!("GET {url} returned {status}"))
}

/// The listener settings the gateway would run with for the same `args`:
/// its config layers, then the flags that replace the HTTP listener.
async fn server_config(args: &[String]) -> anyhow::Result<ServerConfig> {
    let comp = crate::compose::parse(args)?;
    let sources = crate::config::source::gateway_sources(&comp.config).await?;
    let mut config = AppConfig::load_sources(&sources)?;
    crate::compose::apply_tunnel(&mut config, &comp)?;
    if crate::cli::stdio_requested(args) {
        config.gateway.server.transport = TransportMode::Stdio;
    }
    Ok(config.gateway.server)
}

/// Load the gateway's config and probe its health endpoint.
pub async fn check(args: &[String]) -> anyhow::Result<String> {
    let url = probe_url(&server_config(args).await?)?;
    probe(&url, PROBE_TIMEOUT).await
}

/// Print the outcome as one line and return the exit code: 0 for a healthy
/// gateway, 1 for anything else.
pub fn report(outcome: &anyhow::Result<String>) -> i32 {
    match outcome {
        Ok(line) => {
            println!("mcpg --health-check: {line}");
            0
        }
        Err(e) => {
            // A container runtime keeps this line as the probe's log entry.
            let reason = format!("{e:#}").replace(['\r', '\n'], " ");
            eprintln!("mcpg --health-check: {reason}");
            1
        }
    }
}

/// Run `mcpg --health-check` with the arguments after the program name and
/// return the process exit code.
pub fn run(args: &[String]) -> i32 {
    let outcome = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let outcome = runtime.block_on(check(args));
            // A host-name bind resolves on the blocking pool; a lookup that
            // outlives the request timeout must not hold the process open.
            runtime.shutdown_background();
            outcome
        }
        Err(e) => Err(anyhow::Error::new(e).context("cannot build the async runtime")),
    };
    report(&outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TlsConfig, TunnelConfig};

    fn server(bind: &str) -> ServerConfig {
        ServerConfig {
            bind_address: bind.to_owned(),
            ..ServerConfig::default()
        }
    }

    /// A loopback HTTP server that answers `/health` with `status`.
    async fn serve(status: axum::http::StatusCode) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app =
            axum::Router::new().route("/health", axum::routing::get(move || async move { status }));
        tokio::spawn(async move { axum::serve(listener, app).await });
        addr
    }

    /// A loopback port that nothing listens on.
    fn closed_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn a_wildcard_bind_is_probed_on_the_loopback_of_its_family() {
        assert_eq!(local_authority("0.0.0.0:8787"), "127.0.0.1:8787");
        assert_eq!(local_authority("[::]:8787"), "[::1]:8787");
    }

    #[test]
    fn any_other_bind_is_probed_as_written() {
        for bind in [
            "127.0.0.1:9000",
            "10.1.2.3:8787",
            "[::1]:8787",
            "localhost:8787",
        ] {
            assert_eq!(local_authority(bind), bind);
        }
    }

    #[test]
    fn the_probe_url_is_the_configured_health_path_on_loopback() {
        assert_eq!(
            probe_url(&ServerConfig::default()).unwrap(),
            "http://127.0.0.1:8787/health"
        );
        let mut custom = server("0.0.0.0:9090");
        custom.health_path = "/livez".to_owned();
        assert_eq!(probe_url(&custom).unwrap(), "http://127.0.0.1:9090/livez");
    }

    #[test]
    fn a_tls_listener_is_refused_with_its_reason() {
        let mut tls = server("0.0.0.0:8443");
        tls.tls = Some(TlsConfig {
            cert_path: "/etc/mcpg/tls.crt".to_owned(),
            key_path: "/etc/mcpg/tls.key".to_owned(),
            min_tls_version: "1.2".to_owned(),
            client_ca_certs_path: None,
            client_cert_required: Default::default(),
        });
        assert_eq!(local_health_url(&tls), "https://127.0.0.1:8443/health");
        let err = probe_url(&tls).unwrap_err().to_string();
        assert!(
            err.contains("gateway.server.tls") && err.contains("plain HTTP only"),
            "{err}"
        );
    }

    #[test]
    fn a_stdio_gateway_has_no_listener_to_probe() {
        let stdio = ServerConfig {
            transport: TransportMode::Stdio,
            ..ServerConfig::default()
        };
        let err = probe_url(&stdio).unwrap_err().to_string();
        assert!(err.contains("stdio"), "{err}");
    }

    fn tunnel(enabled: bool) -> TunnelConfig {
        TunnelConfig {
            enabled,
            relay_url: "wss://relay.example".to_owned(),
            name: None,
            exposure: Default::default(),
            mode: Default::default(),
        }
    }

    #[test]
    fn a_tunnel_gateway_has_no_listener_to_probe() {
        let tunnelled = ServerConfig {
            tunnel: Some(tunnel(true)),
            ..ServerConfig::default()
        };
        let err = probe_url(&tunnelled).unwrap_err().to_string();
        assert!(
            err.contains("gateway.server.tunnel") && err.contains("no local listener"),
            "{err}"
        );
        let switched_off = ServerConfig {
            tunnel: Some(tunnel(false)),
            ..ServerConfig::default()
        };
        assert_eq!(
            probe_url(&switched_off).unwrap(),
            "http://127.0.0.1:8787/health"
        );
    }

    #[tokio::test]
    async fn the_tunnel_and_stdio_flags_replace_the_listener_as_for_the_gateway() {
        use base64::Engine as _;
        let yaml = "gateway:\n  server:\n    bind_address: \"127.0.0.1:9\"\n";
        let config = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(yaml)
        );
        let argv = |extra: &str| -> Vec<String> {
            ["--health-check", "--config", config.as_str(), extra]
                .map(str::to_owned)
                .to_vec()
        };
        let plain = server_config(&argv("--no-cp")).await.unwrap();
        assert!(probe_url(&plain).is_ok());
        let tunnelled = server_config(&argv("--tunnel")).await.unwrap();
        assert!(tunnelled.tunnel.as_ref().is_some_and(|t| t.enabled));
        assert!(probe_url(&tunnelled).is_err());
        let stdio = server_config(&argv("--stdio")).await.unwrap();
        assert_eq!(stdio.transport, TransportMode::Stdio);
    }

    #[tokio::test]
    async fn a_2xx_answer_exits_0() {
        let addr = serve(axum::http::StatusCode::OK).await;
        let url = probe_url(&server(&addr.to_string())).unwrap();
        let outcome = probe(&url, PROBE_TIMEOUT).await;
        assert_eq!(report(&outcome), 0, "{outcome:?}");
    }

    #[tokio::test]
    async fn a_503_answer_exits_1_and_names_the_status() {
        let addr = serve(axum::http::StatusCode::SERVICE_UNAVAILABLE).await;
        let url = probe_url(&server(&addr.to_string())).unwrap();
        let outcome = probe(&url, PROBE_TIMEOUT).await;
        let reason = format!("{:#}", outcome.as_ref().unwrap_err());
        assert!(reason.contains("503"), "{reason}");
        assert_eq!(report(&outcome), 1);
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_and_exits_1() {
        let addr = serve(axum::http::StatusCode::SEE_OTHER).await;
        let url = probe_url(&server(&addr.to_string())).unwrap();
        let outcome = probe(&url, PROBE_TIMEOUT).await;
        assert_eq!(report(&outcome), 1, "{outcome:?}");
    }

    #[tokio::test]
    async fn no_listener_exits_1() {
        let url = probe_url(&server(&format!("127.0.0.1:{}", closed_port()))).unwrap();
        let outcome = probe(&url, PROBE_TIMEOUT).await;
        assert_eq!(report(&outcome), 1, "{outcome:?}");
    }

    #[tokio::test]
    async fn a_listener_that_never_answers_exits_1_at_the_timeout() {
        // Connections queue in the backlog and are never accepted.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = probe_url(&server(&silent.local_addr().unwrap().to_string())).unwrap();
        let started = std::time::Instant::now();
        let outcome = probe(&url, Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(report(&outcome), 1, "{outcome:?}");
        drop(silent);
    }
}
