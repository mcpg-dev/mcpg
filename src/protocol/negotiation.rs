//! The protocol-version check every request passes before dispatch.
//!
//! The gateway serves MCP `2026-07-28`. A request names the revision it
//! speaks in the `Mcp-Protocol-Version` HTTP header or in
//! `params._meta["io.modelcontextprotocol/protocolVersion"]`; the header
//! wins when both are present (the handler's header validation then
//! requires the two to agree). Any other value is refused with
//! `-32022` (`UnsupportedProtocolVersion`), whose `data.supported` lists
//! the one served revision.
//!
//! An HTTP request that names no revision is refused the same way. A stdio
//! message that names none is served as `2026-07-28`: the process speaks
//! one revision, and its frames carry no headers.

use axum::http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::PROTOCOL_VERSION_HEADER;
use crate::protocol::shared::error::{INVALID_REQUEST_CODE, UNSUPPORTED_PROTOCOL_VERSION_CODE};
use crate::protocol::shared::messages::TransportRejection;
use crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION;
use crate::protocol::v_2026_07_28::wire::meta::META_KEY_PROTOCOL_VERSION;

/// Why a request's protocol version is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolNegotiationError {
    /// The request names a revision other than `2026-07-28`.
    Unsupported { requested: String },
    /// An HTTP request names no revision.
    Missing,
    /// The `Mcp-Protocol-Version` header is not valid UTF-8.
    InvalidHeader,
}

/// Check the protocol revision a request names.
///
/// `headers` is `Some` for HTTP and `None` for stdio.
pub fn negotiate(
    headers: Option<&HeaderMap>,
    body: &Value,
) -> Result<(), ProtocolNegotiationError> {
    if let Some(raw) = headers.and_then(|headers| headers.get(PROTOCOL_VERSION_HEADER)) {
        let header = raw
            .to_str()
            .map_err(|_| ProtocolNegotiationError::InvalidHeader)?;
        return check(header);
    }
    match body
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(META_KEY_PROTOCOL_VERSION))
    {
        Some(Value::String(version)) => check(version),
        Some(other) => Err(ProtocolNegotiationError::Unsupported {
            requested: other.to_string(),
        }),
        None if headers.is_some() => Err(ProtocolNegotiationError::Missing),
        None => Ok(()),
    }
}

fn check(version: &str) -> Result<(), ProtocolNegotiationError> {
    if version == SUPPORTED_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolNegotiationError::Unsupported {
            requested: version.to_owned(),
        })
    }
}

impl ProtocolNegotiationError {
    /// The refusal as a transport rejection: HTTP 400 and a JSON-RPC error.
    ///
    /// - `Unsupported`: `-32022`, with `data.requested` and `data.supported`.
    /// - `Missing`: `-32022`, with `data.supported` only.
    /// - `InvalidHeader`: `-32600` (`InvalidRequest`).
    pub fn into_rejection(self, jsonrpc_id: Option<Value>) -> TransportRejection {
        let supported = [SUPPORTED_PROTOCOL_VERSION];
        let (error_code, message, data) = match self {
            Self::Unsupported { requested } => (
                UNSUPPORTED_PROTOCOL_VERSION_CODE,
                "Unsupported protocol version".to_owned(),
                Some(serde_json::json!({
                    "kind": "unsupported_protocol_version",
                    "requested": requested,
                    "supported": supported,
                })),
            ),
            Self::Missing => (
                UNSUPPORTED_PROTOCOL_VERSION_CODE,
                format!(
                    "The request names no protocol version; send \
                     `Mcp-Protocol-Version: {SUPPORTED_PROTOCOL_VERSION}`"
                ),
                Some(serde_json::json!({
                    "kind": "missing_protocol_version",
                    "supported": supported,
                })),
            ),
            Self::InvalidHeader => (
                INVALID_REQUEST_CODE,
                "Mcp-Protocol-Version header is not valid UTF-8".to_owned(),
                None,
            ),
        };
        TransportRejection {
            status: 400,
            error_code,
            message,
            data,
            jsonrpc_id,
        }
    }
}

impl std::fmt::Display for ProtocolNegotiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { requested } => write!(
                f,
                "unsupported protocol version {requested:?}; supported: \
                 {SUPPORTED_PROTOCOL_VERSION:?}"
            ),
            Self::Missing => write!(
                f,
                "no protocol version named; supported: {SUPPORTED_PROTOCOL_VERSION:?}"
            ),
            Self::InvalidHeader => f.write_str("Mcp-Protocol-Version header is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ProtocolNegotiationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn headers(version: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(PROTOCOL_VERSION_HEADER, version.parse().unwrap());
        headers
    }

    fn body_naming(version: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "_meta": { META_KEY_PROTOCOL_VERSION: version } },
        })
    }

    #[test]
    fn the_served_revision_in_the_header_is_accepted() {
        assert_eq!(
            negotiate(Some(&headers("2026-07-28")), &Value::Null),
            Ok(())
        );
    }

    #[test]
    fn the_served_revision_in_meta_is_accepted_without_a_header() {
        let body = body_naming(json!("2026-07-28"));
        assert_eq!(negotiate(Some(&HeaderMap::new()), &body), Ok(()));
        assert_eq!(negotiate(None, &body), Ok(()));
    }

    #[test]
    fn another_revision_in_the_header_is_unsupported() {
        for version in ["1900-01-01", "2099-12-31", "not-a-version"] {
            assert_eq!(
                negotiate(Some(&headers(version)), &Value::Null),
                Err(ProtocolNegotiationError::Unsupported {
                    requested: version.to_owned()
                }),
                "{version}"
            );
        }
    }

    #[test]
    fn the_header_is_read_before_meta() {
        let body = body_naming(json!("2026-07-28"));
        assert_eq!(
            negotiate(Some(&headers("1900-01-01")), &body),
            Err(ProtocolNegotiationError::Unsupported {
                requested: "1900-01-01".to_owned()
            })
        );
    }

    #[test]
    fn another_revision_in_meta_is_unsupported_on_both_transports() {
        let body = body_naming(json!("1900-01-01"));
        let refused = Err(ProtocolNegotiationError::Unsupported {
            requested: "1900-01-01".to_owned(),
        });
        assert_eq!(negotiate(Some(&HeaderMap::new()), &body), refused);
        assert_eq!(negotiate(None, &body), refused);
    }

    #[test]
    fn a_meta_version_that_is_not_a_string_is_unsupported() {
        let body = body_naming(json!(2026));
        assert_eq!(
            negotiate(None, &body),
            Err(ProtocolNegotiationError::Unsupported {
                requested: "2026".to_owned()
            })
        );
    }

    #[test]
    fn an_http_request_that_names_no_revision_is_refused() {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        assert_eq!(
            negotiate(Some(&HeaderMap::new()), &body),
            Err(ProtocolNegotiationError::Missing)
        );
    }

    #[test]
    fn a_stdio_message_that_names_no_revision_is_served() {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        assert_eq!(negotiate(None, &body), Ok(()));
    }

    #[test]
    fn a_header_that_is_not_utf8_is_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            PROTOCOL_VERSION_HEADER,
            axum::http::HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
        );
        assert_eq!(
            negotiate(Some(&headers), &Value::Null),
            Err(ProtocolNegotiationError::InvalidHeader)
        );
    }

    #[test]
    fn unsupported_renders_requested_and_the_one_served_revision() {
        let rejection = ProtocolNegotiationError::Unsupported {
            requested: "1900-01-01".to_owned(),
        }
        .into_rejection(Some(Value::from(1)));
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.error_code, -32022);
        assert_eq!(rejection.jsonrpc_id, Some(Value::from(1)));
        let data = rejection.data.expect("data");
        assert_eq!(data["kind"], "unsupported_protocol_version");
        assert_eq!(data["requested"], "1900-01-01");
        assert_eq!(data["supported"], json!(["2026-07-28"]));
    }

    #[test]
    fn missing_renders_the_served_revision_without_requested() {
        let rejection = ProtocolNegotiationError::Missing.into_rejection(None);
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.error_code, -32022);
        let data = rejection.data.expect("data");
        assert_eq!(data["supported"], json!(["2026-07-28"]));
        assert!(data.get("requested").is_none());
    }

    #[test]
    fn invalid_header_renders_invalid_request() {
        let rejection = ProtocolNegotiationError::InvalidHeader.into_rejection(None);
        assert_eq!(rejection.status, 400);
        assert_eq!(rejection.error_code, -32600);
        assert!(rejection.data.is_none());
    }
}
