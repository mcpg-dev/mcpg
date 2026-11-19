//! [`SharedServices`] — the bundle of services
//! [`crate::protocol::Handler`] receives at dispatch time beside the
//! runtime itself.
//!
//! Built once at boot in `app::build_from_config` and cloned (cheaply)
//! where needed. Every field is itself an `Arc<...>` so cloning the
//! bundle is reference-counting. The bundle holds what outlives a config
//! reload: the MRTR `request_state_codec`, the MCP Events core and the
//! tunnel's public URL.

#![allow(dead_code)]

use std::sync::Arc;

use crate::config::AppConfig;
use crate::protocol::v_2026_07_28::dispatch::events::EventsHandlerSlot;
#[cfg(test)]
use crate::protocol::v_2026_07_28::dispatch::request_state::InMemoryRequestStateStore;
use crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec;

/// The services [`crate::protocol::Handler`] calls into during dispatch
/// beside the runtime.
///
/// Cloning a `SharedServices` is `Arc::clone` per field — cheap.
#[derive(Clone)]
pub struct SharedServices {
    /// Operator-provided gateway configuration snapshot, captured at
    /// boot. Hot-reload happens at the outer `AppState` layer
    /// (`ArcSwap<AppConfig>`); this `Arc` is replaced on reload by
    /// rebuilding `SharedServices`.
    pub config_snapshot: Arc<AppConfig>,

    /// MRTR `requestState` codec — encodes / decodes the opaque
    /// pipeline-resumption blob carried on
    /// [`InputRequiredResult`](crate::protocol::v_2026_07_28::wire::mrtr::InputRequiredResult).
    /// Encoded when a `tools/call` or `prompts/get` pipeline suspends
    /// awaiting input, and decoded again when the pipeline resumes.
    pub request_state_codec: Arc<RequestStateCodec>,

    /// The MCP Events core, once installed. The bundle outlives config
    /// reloads, so a core installed at boot keeps serving across them.
    pub events: Arc<EventsHandlerSlot>,

    /// The same events core, typed, for the reload path and the inbound
    /// event routes.
    pub events_core: Arc<crate::runtime::events::EventsCoreSlot>,

    /// The URL the relay of a public tunnel assigned this gateway, while
    /// the tunnel is up.
    pub tunnel_public_url: Arc<arc_swap::ArcSwapOption<String>>,

    /// The synthetic-session HMAC state keyed from `config_snapshot`, or
    /// `None` when it configures no key.
    pub synthetic_session_mac: Option<Arc<hmac_sha256::HMAC>>,
}

impl SharedServices {
    /// Construct a bundle from the boot-time configuration snapshot. The
    /// MRTR `requestState` codec is supplied separately so boot wiring can
    /// source the encryption key from operator config.
    pub fn new(
        config_snapshot: Arc<AppConfig>,
        request_state_codec: Arc<RequestStateCodec>,
    ) -> Self {
        use crate::runtime::GatewayRuntime;
        let synthetic_session_mac = GatewayRuntime::synthetic_session_key(&config_snapshot)
            .map(|key| Arc::new(GatewayRuntime::synthetic_session_mac(&key)));
        Self {
            config_snapshot,
            request_state_codec,
            events: Arc::default(),
            events_core: Arc::default(),
            tunnel_public_url: Arc::default(),
            synthetic_session_mac,
        }
    }

    /// A bundle over `config_snapshot` whose MRTR codec has a fixed test
    /// key and the in-memory store, so tests drive the encryption path
    /// without real persistence.
    #[cfg(test)]
    pub fn for_tests(config_snapshot: Arc<AppConfig>) -> Self {
        Self::new(
            config_snapshot,
            Arc::new(RequestStateCodec::new(
                *b"0123456789abcdef0123456789abcdef",
                Arc::new(InMemoryRequestStateStore::new()),
            )),
        )
    }
}

/// A runtime for a protocol-layer test, carrying what dispatch reads of
/// `config` from the runtime: the events config and the embedded
/// authorization server.
#[cfg(test)]
pub(crate) fn test_runtime(config: &AppConfig) -> crate::runtime::GatewayRuntime {
    let mut runtime = crate::runtime::GatewayRuntime::new(
        "mcpg",
        "0.1.0",
        "127.0.0.1:8787",
        "/health",
        "/mcp",
        "info",
        vec![crate::config::SinkConfig {
            kind: "stdout".to_owned(),
            config: serde_json::json!({"format": "json"}),
            level: None,
        }],
        true,
    );
    runtime.set_events_config(config.mcp.configurations.events.clone());
    runtime.set_ema_authorization_server(
        crate::app::build_ema_authorization_server(
            config,
            crate::runtime::authorization_server::ReplayLedger::in_process(),
        )
        .expect("a valid authorization server config"),
    );
    runtime
}
