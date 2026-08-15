//! [`ProtocolRegistry`] — the multi-version dispatcher.
//!
//! Holds an `Arc<dyn ProtocolHandler>` per registered protocol
//! revision and selects the right one for an inbound request based on:
//!
//! 1. The `MCP-Protocol-Version` HTTP header (when present),
//! 2. Then the body's `_meta.io.modelcontextprotocol/protocolVersion`
//!    (modern revisions only),
//! 3. Falling back to [`Self::legacy_default`] when neither is set
//!    (Streamable HTTP spec § "Protocol Version Header").
//!
//! Unknown versions yield a [`ProtocolNegotiationError::Unsupported`]
//! which transports render as HTTP 400 + JSON-RPC error code -32022
//! (`UnsupportedProtocolVersionError`).
//!
//! The single global default is exposed as
//! [`ProtocolRegistry::COMPILE_TIME_DEFAULT`] — one-line flip when the
//! gateway is ready to default to a new revision.

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::messages::TransportRejection;
use crate::protocol::shared::traits::ProtocolHandler;
use crate::protocol::version::ProtocolVersion;

pub use crate::protocol::shared::PROTOCOL_VERSION_HEADER;

/// The multi-version dispatcher.
///
/// One per process, built at boot. Cheap to share by `Arc` — every
/// handler inside is itself an `Arc<dyn ProtocolHandler>`.
pub struct ProtocolRegistry {
    handlers: HashMap<ProtocolVersion, Arc<dyn ProtocolHandler>>,
    advertised: Vec<ProtocolVersion>,
    /// Fallback version used when an inbound request carries neither the
    /// `MCP-Protocol-Version` header nor a body `_meta` version. Pinned
    /// to [`Self::COMPILE_TIME_DEFAULT`] (`V_2025_11_25`); not
    /// operator-overridable.
    legacy_default: ProtocolVersion,
}

impl ProtocolRegistry {
    /// Compile-time default version a fresh `mcpg` configuration will
    /// speak when the operator does not specify `mcp.protocol.default_version`.
    ///
    /// Flipping this constant to a newer revision is the single
    /// global default change — every other call site picks it up
    /// automatically.
    pub const COMPILE_TIME_DEFAULT: ProtocolVersion = ProtocolVersion::V_2025_11_25;

    /// Construct an empty registry. Use [`Self::register`] to add
    /// handlers. The absent-header fallback is pinned to
    /// [`Self::COMPILE_TIME_DEFAULT`].
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            advertised: Vec::new(),
            legacy_default: Self::COMPILE_TIME_DEFAULT,
        }
    }

    /// Register a handler. Idempotent: registering the same version
    /// twice overwrites the previous entry (intended for hot-reload).
    pub fn register(&mut self, handler: Arc<dyn ProtocolHandler>) {
        let version = handler.version();
        if !self.handlers.contains_key(&version) {
            self.advertised.push(version);
        }
        self.handlers.insert(version, handler);
    }

    /// Look up a handler by version.
    pub fn get(&self, version: ProtocolVersion) -> Option<&Arc<dyn ProtocolHandler>> {
        self.handlers.get(&version)
    }

    /// Select the appropriate handler for an inbound request.
    ///
    /// Order of resolution:
    /// 1. `MCP-Protocol-Version` HTTP header.
    /// 2. (Modern revisions only) the body's
    ///    `_meta.io.modelcontextprotocol/protocolVersion` field.
    /// 3. [`Self::legacy_default`] when neither is set.
    ///
    /// Returns [`ProtocolNegotiationError`] when the requested version
    /// is known-format but not registered, or when the header value is
    /// not valid UTF-8.
    pub fn select(
        &self,
        headers: &HeaderMap,
        body: &Value,
    ) -> Result<&Arc<dyn ProtocolHandler>, ProtocolNegotiationError> {
        // 1. HTTP header takes priority when present.
        if let Some(raw) = headers.get(PROTOCOL_VERSION_HEADER) {
            let header = raw
                .to_str()
                .map_err(|_| ProtocolNegotiationError::InvalidHeader)?;
            return self.lookup_string(header);
        }

        // 2. Modern revisions advertise their version in the body's
        //    `_meta`. This branch is inert when only legacy versions
        //    are registered, but the lookup itself is cheap.
        if let Some(version_str) = body
            .get("params")
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
            .and_then(|v| v.as_str())
        {
            return self.lookup_string(version_str);
        }

        // 3. Absent header + absent body meta: legacy fallback.
        self.handlers.get(&self.legacy_default).ok_or_else(|| {
            ProtocolNegotiationError::Unsupported {
                requested: self.legacy_default.as_str().to_owned(),
                supported: self.supported_strings_owned(),
            }
        })
    }

    fn lookup_string(
        &self,
        version_str: &str,
    ) -> Result<&Arc<dyn ProtocolHandler>, ProtocolNegotiationError> {
        let version = ProtocolVersion::parse(version_str).ok_or_else(|| {
            ProtocolNegotiationError::Unsupported {
                requested: version_str.to_owned(),
                supported: self.supported_strings_owned(),
            }
        })?;
        self.handlers
            .get(&version)
            .ok_or_else(|| ProtocolNegotiationError::Unsupported {
                requested: version_str.to_owned(),
                supported: self.supported_strings_owned(),
            })
    }

    fn supported_strings_owned(&self) -> Vec<String> {
        self.advertised
            .iter()
            .map(|v| v.as_str().to_owned())
            .collect()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Why version negotiation failed.
#[derive(Debug, Clone)]
pub enum ProtocolNegotiationError {
    /// Version requested isn't in the registered handler set.
    Unsupported {
        requested: String,
        supported: Vec<String>,
    },
    /// `MCP-Protocol-Version` header was present but not valid UTF-8.
    InvalidHeader,
}

impl ProtocolNegotiationError {
    /// Convert to a [`TransportRejection`] the HTTP transport can
    /// emit as a 400 with a JSON-RPC error body.
    ///
    /// - `Unsupported`: code -32022 (`UnsupportedProtocolVersionError`,
    ///   the MCP-reserved-band code adopted in `2026-07-28`)
    /// - `InvalidHeader`: code -32600 (`InvalidRequest`)
    pub fn into_rejection(self, jsonrpc_id: Option<Value>) -> TransportRejection {
        match self {
            Self::Unsupported {
                requested,
                supported,
            } => TransportRejection {
                status: 400,
                error_code: crate::protocol::shared::error::UNSUPPORTED_PROTOCOL_VERSION_CODE,
                message: "Unsupported protocol version".to_owned(),
                data: Some(serde_json::json!({
                    "supported": supported,
                    "requested": requested,
                })),
                jsonrpc_id,
            },
            Self::InvalidHeader => TransportRejection {
                status: 400,
                error_code: -32600,
                message: "Mcp-Protocol-Version header is not valid UTF-8".to_owned(),
                data: None,
                jsonrpc_id,
            },
        }
    }
}

impl std::fmt::Display for ProtocolNegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported {
                requested,
                supported,
            } => write!(
                f,
                "unsupported protocol version {requested:?}; supported: {supported:?}"
            ),
            Self::InvalidHeader => write!(f, "Mcp-Protocol-Version header is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ProtocolNegotiationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_default_is_2025_11_25() {
        assert_eq!(
            ProtocolRegistry::COMPILE_TIME_DEFAULT,
            ProtocolVersion::V_2025_11_25
        );
    }

    #[test]
    fn negotiation_error_renders_unsupported_with_supported_list() {
        let err = ProtocolNegotiationError::Unsupported {
            requested: "1900-01-01".to_owned(),
            supported: vec!["2025-11-25".to_owned()],
        };
        let rejection = err.into_rejection(Some(Value::from(1)));
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.error_code, -32022);
        let data = rejection.data.expect("data");
        assert_eq!(data["requested"], "1900-01-01");
        assert_eq!(data["supported"][0], "2025-11-25");
    }

    #[test]
    fn negotiation_error_renders_invalid_header_with_invalid_request() {
        let rejection = ProtocolNegotiationError::InvalidHeader.into_rejection(None);
        assert_eq!(rejection.error_code, -32600);
        assert_eq!(rejection.status, 400);
    }

    // ── Two-handler negotiation ─────────────────────────────────

    fn registry_with_both_handlers() -> ProtocolRegistry {
        let mut registry = ProtocolRegistry::new();
        registry.register(Arc::new(crate::protocol::v_2025_11_25::Handler::new()));
        registry.register(Arc::new(crate::protocol::v_2026_07_28::Handler::new()));
        registry
    }

    #[test]
    fn select_resolves_legacy_header_to_legacy_handler() {
        let r = registry_with_both_handlers();
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, "2025-11-25".parse().unwrap());
        let handler = r.select(&headers, &Value::Null).expect("legacy handler");
        assert_eq!(handler.version(), ProtocolVersion::V_2025_11_25);
        assert_eq!(handler.version_string(), "2025-11-25");
    }

    #[test]
    fn select_resolves_modern_draft_header_to_modern_handler() {
        let r = registry_with_both_handlers();
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, "DRAFT-2026-v1".parse().unwrap());
        let handler = r.select(&headers, &Value::Null).expect("modern handler");
        assert_eq!(handler.version(), ProtocolVersion::V_2026_07_28);
        // Inbound accepts the pre-final alias; the handler reports the
        // final wire string outbound.
        assert_eq!(handler.version_string(), "2026-07-28");
    }

    #[test]
    fn select_resolves_modern_final_header_to_modern_handler() {
        // Clients pinning the post-final wire string `2026-07-28`
        // hit the same handler as `DRAFT-2026-v1` clients (parse
        // accepts both strings).
        let r = registry_with_both_handlers();
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, "2026-07-28".parse().unwrap());
        let handler = r.select(&headers, &Value::Null).expect("modern handler");
        assert_eq!(handler.version(), ProtocolVersion::V_2026_07_28);
    }

    #[test]
    fn select_absent_header_falls_through_to_legacy_default() {
        // No header, no body meta — the registry returns the
        // handler at `legacy_default` (= COMPILE_TIME_DEFAULT =
        // V_2025_11_25). Streamable HTTP spec §"Protocol Version
        // Header".
        let r = registry_with_both_handlers();
        let handler = r.select(&HeaderMap::new(), &Value::Null).expect("default");
        assert_eq!(handler.version(), ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn select_unknown_header_yields_unsupported_with_both_handlers_listed() {
        let r = registry_with_both_handlers();
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, "1900-01-01".parse().unwrap());
        match r.select(&headers, &Value::Null) {
            Err(ProtocolNegotiationError::Unsupported { supported, .. }) => {
                assert!(supported.iter().any(|s| s == "2025-11-25"));
                assert!(supported.iter().any(|s| s == "2026-07-28"));
            }
            Err(other) => panic!("expected Unsupported variant, got {other}"),
            Ok(_) => panic!("unknown version must NOT resolve to a handler"),
        }
    }

    #[test]
    fn select_resolves_modern_body_meta_when_header_absent() {
        let r = registry_with_both_handlers();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "DRAFT-2026-v1"
                }
            }
        });
        let handler = r.select(&HeaderMap::new(), &body).expect("modern handler");
        assert_eq!(handler.version(), ProtocolVersion::V_2026_07_28);
    }
}
