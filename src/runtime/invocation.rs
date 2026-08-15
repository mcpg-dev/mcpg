//! Shared invocation-surface types.
//!
//! Every backend call compiles to one generic `BackendInvocationRoute` per
//! binding; the raw backend response is decoded directly into whichever MCP
//! surface the caller asked for, preserving native metadata (annotations,
//! multimodal content, binary resources, …). This module names the surface
//! contract: an explicit `InvocationSurface` enum and surface-specific
//! decoding errors the runtime uses to turn a backend response into a tool,
//! prompt, resource, resource-template, or completion result.

use crate::protocol::{
    BlobResourceContents, PromptGetResult, PromptMessage, ResourceContents, ResourceReadResult,
    ResourceTextContents, ToolCallResult, ToolContent,
};

/// MCP surface a backend invocation is serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationSurface {
    Tool,
    Prompt,
    Resource,
    ResourceTemplate,
    Completion,
}

impl InvocationSurface {
    pub fn as_label(self) -> &'static str {
        match self {
            InvocationSurface::Tool => "tool",
            InvocationSurface::Prompt => "prompt",
            InvocationSurface::Resource => "resource",
            InvocationSurface::ResourceTemplate => "resource_template",
            InvocationSurface::Completion => "completion",
        }
    }
}

/// Surface-specific decode failure. Surfaces return this when the backend
/// response cannot be projected onto the requested MCP surface. The runtime
/// converts these into JSON-RPC errors (`-32603` internal error) with a
/// descriptive message rather than silently degrading to a fallback.
#[derive(Debug, Clone)]
pub enum SurfaceDecodeError {
    /// Backend flagged the call as an error; decoders cannot project an
    /// `isError: true` tool result onto non-tool surfaces.
    BackendError { message: String },
    /// Backend response had no text/blob content at all.
    EmptyResponse,
    /// Backend response is present but does not match the surface contract.
    MalformedResponse { reason: String },
}

impl std::fmt::Display for SurfaceDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SurfaceDecodeError::BackendError { message } => {
                write!(f, "backend returned an error response: {message}")
            }
            SurfaceDecodeError::EmptyResponse => write!(f, "backend response was empty"),
            SurfaceDecodeError::MalformedResponse { reason } => {
                write!(
                    f,
                    "backend response is not a valid surface envelope: {reason}"
                )
            }
        }
    }
}

/// Extract the first textual body from a tool-call-shaped backend response.
/// MCP 2025-11-25 prompt and resource bindings produce their native shapes
/// as JSON which, for legacy backend compatibility, is delivered through a
/// `ToolContent::Text` entry. This helper pulls that body out deterministically
/// rather than relying on the "try every content item" scan the old code used.
fn primary_text_body(result: &ToolCallResult) -> Option<&str> {
    for content in &result.content {
        if let ToolContent::Text { text, .. } = content {
            return Some(text.as_str());
        }
    }
    None
}

/// Decode a backend tool-call response as a native prompt result.
///
/// The backend contract for prompt bindings is
/// `{ "messages": [{ "role": "...", "content": {...} }, ...] }`. Unlike the
/// prior adapter, this decoder validates the shape strictly and returns
/// [`SurfaceDecodeError`] on any deviation; callers surface a JSON-RPC error
/// so contract violations are visible rather than silently downgraded to a
/// single "assistant" wrapper message.
pub fn decode_prompt_result(
    result: &ToolCallResult,
) -> Result<PromptGetResult, SurfaceDecodeError> {
    if result.is_error {
        let message = primary_text_body(result)
            .unwrap_or("tool returned isError without a text body")
            .to_owned();
        return Err(SurfaceDecodeError::BackendError { message });
    }

    let body = primary_text_body(result).ok_or(SurfaceDecodeError::EmptyResponse)?;
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|err| SurfaceDecodeError::MalformedResponse {
            reason: format!("prompt body is not JSON: {err}"),
        })?;

    let messages_value = parsed
        .get("messages")
        .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
            reason: "prompt body is missing `messages`".to_owned(),
        })?
        .clone();

    // accept the full MCP 2025-11-25 content-block surface
    // (text / image / audio / resource_link / resource) by leaning on
    // serde — `PromptMessage` and `PromptMessageContent` now
    // round-trip. serde enforces the variant-specific required fields
    // (e.g. image.data + image.mimeType); any deviation surfaces as a
    // MalformedResponse error.
    let messages: Vec<PromptMessage> = serde_json::from_value(messages_value).map_err(|err| {
        SurfaceDecodeError::MalformedResponse {
            reason: format!("prompt `messages` does not match the spec content-block shape: {err}"),
        }
    })?;
    if messages.is_empty() {
        return Err(SurfaceDecodeError::MalformedResponse {
            reason: "`messages` must contain at least one entry".to_owned(),
        });
    }

    Ok(PromptGetResult { messages })
}

/// Decode a backend tool-call response as a native resource-read result.
///
/// Backend contract: `{ "contents": [{ "uri": "...", ("text"|"blob"): "...", "mimeType"?: "..." }] }`.
/// The decoder enforces that each entry is exclusively text or blob and that
/// `uri` is present. `requested_uri` is used only to enrich the error message.
pub fn decode_resource_result(
    result: &ToolCallResult,
    requested_uri: &str,
) -> Result<ResourceReadResult, SurfaceDecodeError> {
    if result.is_error {
        let message = primary_text_body(result)
            .unwrap_or("tool returned isError without a text body")
            .to_owned();
        return Err(SurfaceDecodeError::BackendError { message });
    }

    let body = primary_text_body(result).ok_or(SurfaceDecodeError::EmptyResponse)?;
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|err| SurfaceDecodeError::MalformedResponse {
            reason: format!("resource body for {requested_uri} is not JSON: {err}"),
        })?;

    let contents_value =
        parsed
            .get("contents")
            .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
                reason: format!("resource body for {requested_uri} is missing `contents`"),
            })?;
    let contents_array =
        contents_value
            .as_array()
            .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
                reason: "`contents` must be an array".to_owned(),
            })?;
    if contents_array.is_empty() {
        return Err(SurfaceDecodeError::MalformedResponse {
            reason: format!("`contents` for {requested_uri} must contain at least one entry"),
        });
    }

    let mut contents = Vec::with_capacity(contents_array.len());
    for (idx, entry) in contents_array.iter().enumerate() {
        let uri = entry
            .get("uri")
            .and_then(|u| u.as_str())
            .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
                reason: format!("contents[{idx}].uri must be a string"),
            })?
            .to_owned();
        let mime_type = entry
            .get("mimeType")
            .and_then(|m| m.as_str())
            .map(|m| m.to_owned());
        // Preserve per-content `_meta` (notably SEP-1865 `_meta.ui`) so
        // a native `kind: resource` binding serving a `ui://` resource
        // round-trips its CSP/permissions envelope.
        let meta = entry.get("_meta").cloned();
        let has_text = entry.get("text").is_some();
        let has_blob = entry.get("blob").is_some();
        if has_text && has_blob {
            return Err(SurfaceDecodeError::MalformedResponse {
                reason: format!("contents[{idx}] cannot carry both `text` and `blob`"),
            });
        }
        if has_blob {
            let blob = entry
                .get("blob")
                .and_then(|b| b.as_str())
                .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
                    reason: format!("contents[{idx}].blob must be a string"),
                })?
                .to_owned();
            contents.push(ResourceContents::Blob(BlobResourceContents {
                uri,
                mime_type,
                blob,
                meta,
            }));
        } else {
            let text = entry
                .get("text")
                .and_then(|t| t.as_str())
                .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
                    reason: format!("contents[{idx}] must carry either `text` or `blob`"),
                })?
                .to_owned();
            contents.push(ResourceContents::Text(ResourceTextContents {
                uri,
                mime_type,
                text,
                meta,
            }));
        }
    }

    Ok(ResourceReadResult {
        contents,
        ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
        cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
        cache_token: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_result_text(body: &str) -> ToolCallResult {
        ToolCallResult {
            content: vec![ToolContent::text(body.to_owned())],
            structured_content: None,
            is_error: false,
            meta: None,
        }
    }

    use crate::protocol::PromptMessageContent;

    #[test]
    fn decode_prompt_accepts_native_messages() {
        let result = tool_result_text(
            r#"{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}"#,
        );
        let got = decode_prompt_result(&result).expect("decoded");
        assert_eq!(got.messages.len(), 1);
        assert_eq!(got.messages[0].role, "user");
        match &got.messages[0].content {
            PromptMessageContent::Text { text, .. } => assert_eq!(text, "hi"),
            other => panic!("unexpected content: {other:?}"),
        }
    }

    #[test]
    fn decode_prompt_accepts_image_audio_resource_link_and_embedded_resource() {
        let result = tool_result_text(
            r#"{"messages":[
                {"role":"user","content":{"type":"text","text":"t"}},
                {"role":"assistant","content":{"type":"image","data":"AQID","mimeType":"image/png"}},
                {"role":"assistant","content":{"type":"audio","data":"AQID","mimeType":"audio/wav"}},
                {"role":"assistant","content":{"type":"resource_link","uri":"r://a","name":"A"}},
                {"role":"assistant","content":{"type":"resource","resource":{"uri":"r://b","text":"x"}}}
            ]}"#,
        );
        let got = decode_prompt_result(&result).expect("decoded");
        assert_eq!(got.messages.len(), 5);
        assert!(matches!(
            got.messages[0].content,
            PromptMessageContent::Text { .. }
        ));
        assert!(matches!(
            got.messages[1].content,
            PromptMessageContent::Image { .. }
        ));
        assert!(matches!(
            got.messages[2].content,
            PromptMessageContent::Audio { .. }
        ));
        assert!(matches!(
            got.messages[3].content,
            PromptMessageContent::ResourceLink { .. }
        ));
        assert!(matches!(
            got.messages[4].content,
            PromptMessageContent::Resource { .. }
        ));
    }

    #[test]
    fn decode_prompt_rejects_missing_messages() {
        let result = tool_result_text("{}");
        let err = decode_prompt_result(&result).expect_err("missing messages");
        assert!(matches!(err, SurfaceDecodeError::MalformedResponse { .. }));
    }

    #[test]
    fn decode_prompt_rejects_tool_error() {
        let result = ToolCallResult {
            content: vec![ToolContent::text("boom".to_owned())],
            structured_content: None,
            is_error: true,
            meta: None,
        };
        let err = decode_prompt_result(&result).expect_err("tool-error propagates");
        assert!(matches!(err, SurfaceDecodeError::BackendError { .. }));
    }

    #[test]
    fn decode_resource_accepts_blob_and_text() {
        let result = tool_result_text(
            r#"{"contents":[
                {"uri":"r://a","text":"hello","mimeType":"text/plain"},
                {"uri":"r://b","blob":"AAEC","mimeType":"application/octet-stream"}
            ]}"#,
        );
        let got = decode_resource_result(&result, "r://request").expect("decoded");
        assert_eq!(got.contents.len(), 2);
        match &got.contents[0] {
            ResourceContents::Text(t) => {
                assert_eq!(t.uri, "r://a");
                assert_eq!(t.text, "hello");
            }
            other => panic!("expected text, got {other:?}"),
        }
        match &got.contents[1] {
            ResourceContents::Blob(b) => {
                assert_eq!(b.uri, "r://b");
                assert_eq!(b.blob, "AAEC");
            }
            other => panic!("expected blob, got {other:?}"),
        }
    }

    #[test]
    fn decode_resource_rejects_mixed_text_and_blob_entry() {
        let result = tool_result_text(r#"{"contents":[{"uri":"r://a","text":"x","blob":"AA"}]}"#);
        let err = decode_resource_result(&result, "r://a").expect_err("mixed rejected");
        assert!(matches!(err, SurfaceDecodeError::MalformedResponse { .. }));
    }

    #[test]
    fn decode_resource_rejects_empty_body() {
        let result = ToolCallResult {
            content: vec![],
            structured_content: None,
            is_error: false,
            meta: None,
        };
        let err = decode_resource_result(&result, "r://a").expect_err("empty rejected");
        assert!(matches!(err, SurfaceDecodeError::EmptyResponse));
    }
}
