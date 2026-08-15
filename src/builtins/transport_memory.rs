//! Built-in `transport` plugin — `dev.mcpg.builtin.transport.memory`.
//!
//! In-memory channel-backed transport. Unlike HTTP / stdio (which
//! own real file descriptors), the memory transport exposes a
//! programmatic `send` method that callers invoke directly —
//! messages pushed via `send` route straight through the
//! dispatcher the operator handed in at `start`, and the
//! dispatcher's reply is handed back to the `send` caller.
//!
//! # What it's for
//!
//! Three use cases:
//!
//! 1. **Tests.** Exercise the full `Transport` + `MessageDispatcher`
//!    compose without booting a real server — the `transport_e2e`
//!    integration test uses this.
//!
//! 2. **Embedded gateways.** A downstream crate embedding MCPG
//!    in-process can wire its own client-side send-loop to the
//!    memory transport and bypass the wire entirely.
//!
//! 3. **Reference implementation.** The simplest legal `Transport`
//!    impl — new transport authors read this first.
//!
//! Real HTTP / stdio migrations land as follow-ups alongside the
//! runtime-side `MessageDispatcher` implementation.
//!
//! # Not auto-bound
//!
//! Unlike `secret.env` + `secret.file` + `config.file` (auto-bound
//! at gateway boot so plugins can depend on the built-in), the
//! memory transport is NOT auto-enabled. Operators opt in via
//! `plugins.transports.memory-v1.enabled: true`. The gateway's
//! default listener path is unchanged.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use mcpg_plugin_protocol::{
    PluginClass, PluginManifest,
    transport::{
        DispatchResponse, DispatcherError, MessageDispatcher, Transport, TransportError,
        TransportHandle,
    },
};

pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.transport.memory
name: Built-in Memory Transport
description: |
  Gateway-bundled transport: in-memory channel-backed message
  delivery. Exposes a programmatic `send(session_id, bytes)` method
  that routes through the dispatcher. Not auto-bound at gateway
  boot — operators opt in via `plugins.transports.memory-v1`. Use
  cases: tests, embedded gateways, transport reference impl.
class: transport
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// Per-start state. `dispatcher: None` means the transport isn't
/// currently accepting sends — either pre-start or post-close.
struct State {
    dispatcher: Option<Arc<dyn MessageDispatcher>>,
}

pub struct MemoryTransport {
    manifest: PluginManifest,
    state: Arc<Mutex<State>>,
}

impl MemoryTransport {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.transport.memory".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in Memory Transport".into(),
                plugin_class: PluginClass::Transport,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: vec![],
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            state: Arc::new(Mutex::new(State { dispatcher: None })),
        })
    }

    /// Push a message into the transport. Routes through the
    /// dispatcher the operator handed in at `start`. Returns
    /// whatever the dispatcher returned.
    ///
    /// Returns `DispatcherError::Shutdown` if the transport
    /// hasn't been started yet (or was already closed). Maps
    /// `not-started` to the `Shutdown` kind rather than minting a
    /// new variant because, to the caller, "transport is closed"
    /// and "transport was never opened" look the same.
    pub async fn send(
        &self,
        session_id: &str,
        message: Bytes,
    ) -> Result<DispatchResponse, DispatcherError> {
        let dispatcher = {
            let guard = self
                .state
                .lock()
                .expect("memory transport state mutex poisoned");
            guard.dispatcher.as_ref().map(Arc::clone)
        };
        let Some(dispatcher) = dispatcher else {
            return Err(DispatcherError::Shutdown);
        };
        dispatcher.dispatch(session_id, message).await
    }

    /// Whether the transport is currently accepting sends.
    /// True between `start` and `close`.
    pub fn is_listening(&self) -> bool {
        self.state
            .lock()
            .expect("memory transport state mutex poisoned")
            .dispatcher
            .is_some()
    }
}

struct MemoryHandle {
    state: Arc<Mutex<State>>,
}

#[mcpg_plugin_protocol::async_trait]
impl TransportHandle for MemoryHandle {
    async fn listen_address(&self) -> Option<String> {
        // Memory transport has no network-visible address.
        Some("memory".to_owned())
    }

    async fn close(&self) {
        let mut guard = self
            .state
            .lock()
            .expect("memory transport state mutex poisoned");
        guard.dispatcher = None;
    }
}

#[mcpg_plugin_protocol::async_trait]
impl Transport for MemoryTransport {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn name(&self) -> &str {
        "memory-v1"
    }

    async fn start(
        &self,
        _listener_config: &serde_json::Value,
        dispatcher: Arc<dyn MessageDispatcher>,
    ) -> Result<Box<dyn TransportHandle>, TransportError> {
        let mut guard = self
            .state
            .lock()
            .expect("memory transport state mutex poisoned");
        if guard.dispatcher.is_some() {
            return Err(TransportError::AlreadyListening);
        }
        guard.dispatcher = Some(dispatcher);
        Ok(Box::new(MemoryHandle {
            state: Arc::clone(&self.state),
        }))
    }

    async fn shutdown(&self) {
        // Clear dispatcher on shutdown so any in-flight `send`
        // that lost the race with shutdown returns cleanly.
        let mut guard = self
            .state
            .lock()
            .expect("memory transport state mutex poisoned");
        guard.dispatcher = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoDispatcher;

    #[mcpg_plugin_protocol::async_trait]
    impl MessageDispatcher for EchoDispatcher {
        async fn dispatch(
            &self,
            _session_id: &str,
            message: Bytes,
        ) -> Result<DispatchResponse, DispatcherError> {
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&message);
            Ok(DispatchResponse::unary(reply))
        }
    }

    struct RecordingDispatcher {
        calls: std::sync::Mutex<Vec<(String, Bytes)>>,
    }

    #[mcpg_plugin_protocol::async_trait]
    impl MessageDispatcher for RecordingDispatcher {
        async fn dispatch(
            &self,
            session_id: &str,
            message: Bytes,
        ) -> Result<DispatchResponse, DispatcherError> {
            self.calls
                .lock()
                .unwrap()
                .push((session_id.to_owned(), message));
            Ok(DispatchResponse::ack())
        }
    }

    #[tokio::test]
    async fn send_routes_through_dispatcher() {
        let t = MemoryTransport::new();
        let _handle = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        let resp = t.send("s1", Bytes::from_static(b"hello")).await.unwrap();
        assert_eq!(resp.reply.as_deref(), Some(b"echo:hello".as_slice()));
    }

    #[tokio::test]
    async fn send_without_start_returns_shutdown() {
        let t = MemoryTransport::new();
        let err = t
            .send("s1", Bytes::from_static(b"hello"))
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "shutdown");
    }

    #[tokio::test]
    async fn send_after_close_returns_shutdown() {
        let t = MemoryTransport::new();
        let handle = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        handle.close().await;
        assert!(!t.is_listening());
        let err = t
            .send("s1", Bytes::from_static(b"hello"))
            .await
            .unwrap_err();
        assert_eq!(err.kind_label(), "shutdown");
    }

    #[tokio::test]
    async fn double_start_refused() {
        let t = MemoryTransport::new();
        let _h = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        match t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
        {
            Err(e) => assert_eq!(e.kind_label(), "already_listening"),
            Ok(_) => panic!("expected already_listening"),
        }
    }

    #[tokio::test]
    async fn restart_after_close_ok() {
        let t = MemoryTransport::new();
        let h1 = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        h1.close().await;
        // Closing frees the slot; a second start succeeds.
        let _h2 = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        assert!(t.is_listening());
    }

    #[tokio::test]
    async fn dispatcher_receives_session_id_and_bytes() {
        let rec = Arc::new(RecordingDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let t = MemoryTransport::new();
        let _h = t
            .start(
                &serde_json::Value::Null,
                Arc::clone(&rec) as Arc<dyn MessageDispatcher>,
            )
            .await
            .unwrap();
        t.send("session-alpha", Bytes::from_static(b"frame-1"))
            .await
            .unwrap();
        t.send("session-beta", Bytes::from_static(b"frame-2"))
            .await
            .unwrap();
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "session-alpha");
        assert_eq!(calls[0].1.as_ref(), b"frame-1");
        assert_eq!(calls[1].0, "session-beta");
        assert_eq!(calls[1].1.as_ref(), b"frame-2");
    }

    #[tokio::test]
    async fn handle_reports_memory_listen_address() {
        let t = MemoryTransport::new();
        let h = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        assert_eq!(h.listen_address().await.as_deref(), Some("memory"));
    }

    #[tokio::test]
    async fn shutdown_clears_dispatcher() {
        let t = MemoryTransport::new();
        let _h = t
            .start(&serde_json::Value::Null, Arc::new(EchoDispatcher))
            .await
            .unwrap();
        assert!(t.is_listening());
        t.shutdown().await;
        assert!(!t.is_listening());
    }

    #[test]
    fn transport_name_is_memory_v1() {
        let t = MemoryTransport::new();
        assert_eq!(t.name(), "memory-v1");
    }

    #[test]
    fn descriptor_yaml_parses_as_transport() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert_eq!(d.id, "dev.mcpg.builtin.transport.memory");
        assert_eq!(d.class, PluginClass::Transport);
    }
}
