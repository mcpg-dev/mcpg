//! [`SharedServices`] — the bundle of runtime services every
//! [`ProtocolHandler`](crate::protocol::shared::traits::ProtocolHandler)
//! impl receives at dispatch time.
//!
//! Built once at boot in `app::build_from_config` and cloned (cheaply)
//! into each handler. Every field is itself an `Arc<...>` so cloning
//! the bundle is reference-counting.
//!
//! Handlers reach the gateway's runtime services (capability/plugin
//! registries, gates, stores, buses, the execution dispatcher,
//! pipeline engine, observability) through the [`GatewayRuntime`]
//! handle held here, plus the MRTR `request_state_codec` carried
//! directly on the bundle.

#![allow(dead_code)]

use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;

use crate::config::AppConfig;
#[cfg(test)]
use crate::protocol::v_2026_07_28::dispatch::request_state::InMemoryRequestStateStore;
use crate::protocol::v_2026_07_28::dispatch::request_state::RequestStateCodec;
use crate::runtime::GatewayRuntime;

/// All version-blind runtime services that
/// [`ProtocolHandler`](crate::protocol::shared::traits::ProtocolHandler)
/// implementations call into during dispatch.
///
/// Cloning a `SharedServices` is `Arc::clone` per field — cheap.
///
/// The bundle holds two handles:
/// - `config_snapshot` — the operator config at boot time.
/// - `runtime` — a **`Weak`** handle to the live
///   `Arc<ArcSwap<GatewayRuntime>>`. The `Weak` is the key to avoid
///   a memory leak: `GatewayRuntime` holds an
///   `Arc<SharedServices>`; if `SharedServices` held a *strong*
///   `Arc<ArcSwap<GatewayRuntime>>` we would form a reference cycle
///   between the runtime, its bundle, and the swap cell. Handlers
///   upgrade the `Weak` to a strong `Arc` transiently per dispatch
///   call — the upgrade always succeeds during a real in-flight
///   request because the transport keeps the runtime alive for the
///   call's lifetime.
///
/// Holding the whole runtime as one handle (rather than per-service
/// Arcs) is a pragmatic shortcut: it gives handlers everything they
/// need (capability registry, plugin registry, gates, stores, buses,
/// execution dispatcher, pipeline engine, observability) without
/// re-plumbing each field through the bundle. Future passes can
/// slim the bundle down to per-service Arcs as fields are factored
/// out of `GatewayRuntime`.
#[derive(Clone)]
pub struct SharedServices {
    /// Operator-provided gateway configuration snapshot, captured at
    /// boot. Hot-reload happens at the outer `AppState` layer
    /// (`ArcSwap<AppConfig>`); this `Arc` is replaced on reload by
    /// rebuilding `SharedServices`.
    pub config_snapshot: Arc<AppConfig>,

    /// Live [`GatewayRuntime`] handle (held weakly to avoid the
    /// runtime→services→runtime cycle described above). Use
    /// [`Self::runtime`] to obtain a strong `Arc<ArcSwap<...>>` for
    /// dispatch.
    runtime: Weak<ArcSwap<GatewayRuntime>>,

    /// MRTR `requestState` codec — encodes / decodes the opaque
    /// pipeline-resumption blob carried on
    /// [`InputRequiredResult`](crate::protocol::v_2026_07_28::wire::mrtr::InputRequiredResult).
    /// Encoded when the modern `tools/call` path suspends awaiting
    /// input, and decoded again when the pipeline resumes.
    pub request_state_codec: Arc<RequestStateCodec>,
}

impl SharedServices {
    /// Construct a bundle from the boot-time configuration snapshot
    /// and the gateway runtime swap handle. The runtime handle is
    /// stored weakly internally. The MRTR `requestState` codec is
    /// supplied separately so boot wiring can source the encryption
    /// key from operator config.
    pub fn new(
        config_snapshot: Arc<AppConfig>,
        runtime: &Arc<ArcSwap<GatewayRuntime>>,
        request_state_codec: Arc<RequestStateCodec>,
    ) -> Self {
        Self {
            config_snapshot,
            runtime: Arc::downgrade(runtime),
            request_state_codec,
        }
    }

    /// Upgrade the runtime handle and return the strong
    /// `Arc<ArcSwap<GatewayRuntime>>`. Returns `None` only if the
    /// gateway is in the process of shutting down and the outer
    /// [`AppState`](crate::app::AppState) has already dropped its
    /// runtime — in normal in-flight dispatch this always succeeds.
    pub fn runtime(&self) -> Option<Arc<ArcSwap<GatewayRuntime>>> {
        self.runtime.upgrade()
    }

    /// Test-only constructor that produces a [`SharedServices`] whose
    /// `runtime` `Weak` is unupgradeable. Useful for unit tests that
    /// exercise the shutdown-mid-dispatch path on a
    /// [`ProtocolHandler`](crate::protocol::shared::traits::ProtocolHandler)
    /// without standing up a full `GatewayRuntime` fixture. The
    /// MRTR codec is minted with a deterministic test key + the
    /// in-memory store so tests can drive the encryption path
    /// without standing up real persistence.
    #[cfg(test)]
    pub fn with_no_runtime(config_snapshot: Arc<AppConfig>) -> Self {
        Self {
            config_snapshot,
            runtime: Weak::new(),
            request_state_codec: Arc::new(RequestStateCodec::new(
                *b"0123456789abcdef0123456789abcdef",
                Arc::new(InMemoryRequestStateStore::new()),
            )),
        }
    }
}
