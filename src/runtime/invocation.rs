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
    decode_resource_contents(&parsed, requested_uri)
}

/// Decode a resource binding's answer: an `http` binding's through
/// [`decode_http_resource_result`], any other strictly.
pub fn decode_binding_resource_result(
    route: &crate::backends::BackendInvocationRoute,
    result: &ToolCallResult,
    requested_uri: &str,
    mime_type: Option<&str>,
) -> Result<ResourceReadResult, SurfaceDecodeError> {
    match route {
        crate::backends::BackendInvocationRoute::NetworkJsonCall { .. }
        | crate::backends::BackendInvocationRoute::NetworkQueryCall { .. } => {
            decode_http_resource_result(result, requested_uri, mime_type)
        }
        _ => decode_resource_result(result, requested_uri),
    }
}

/// Decode an `http` binding's answer as a resource-read result. The binding
/// answers its call envelope; the upstream's body is the resource. A body that
/// decodes as MCP `contents` is served as those contents, any other body as the
/// one text content of `requested_uri`, typed `mime_type` (else the response's
/// content type). A body cut at the binding's `max_response_bytes`, or one that
/// is not UTF-8, is refused: a resource is neither served nor watched in part or
/// damaged.
pub fn decode_http_resource_result(
    result: &ToolCallResult,
    requested_uri: &str,
    mime_type: Option<&str>,
) -> Result<ResourceReadResult, SurfaceDecodeError> {
    if result.is_error {
        let message = primary_text_body(result)
            .unwrap_or("tool returned isError without a text body")
            .to_owned();
        return Err(SurfaceDecodeError::BackendError { message });
    }
    let response = result
        .structured_content
        .as_ref()
        .and_then(|envelope| envelope.get("response"))
        .ok_or_else(|| SurfaceDecodeError::MalformedResponse {
            reason: format!("the http answer for {requested_uri} carries no response"),
        })?;
    if response
        .get("bodyTruncated")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Err(SurfaceDecodeError::MalformedResponse {
            reason: format!(
                "the body of {requested_uri} is longer than the binding's max_response_bytes"
            ),
        });
    }
    if let Some(read) = response
        .get("json")
        .and_then(|json| decode_resource_contents(json, requested_uri).ok())
    {
        return Ok(read);
    }
    let text = response
        .get("body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    // The plugin reads the body lossily, so a replacement character marks bytes
    // that were not UTF-8: serving them would hand out a damaged copy.
    if text.contains(char::REPLACEMENT_CHARACTER) {
        return Err(SurfaceDecodeError::MalformedResponse {
            reason: format!("the body of {requested_uri} is not UTF-8 text"),
        });
    }
    let mime_type = mime_type
        .or_else(|| {
            response
                .get("contentType")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned);
    Ok(ResourceReadResult {
        contents: vec![ResourceContents::Text(ResourceTextContents {
            uri: requested_uri.to_owned(),
            mime_type,
            text,
            meta: None,
        })],
        ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
        cache_scope: Some(crate::protocol::shared::caching::CacheScope::Private),
        cache_token: None,
    })
}

/// Decode the MCP `contents` of a resource-read answer.
fn decode_resource_contents(
    parsed: &serde_json::Value,
    requested_uri: &str,
) -> Result<ResourceReadResult, SurfaceDecodeError> {
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

    /// An `http` binding's answer: the plugin's envelope around `response`.
    fn http_answer(response: serde_json::Value) -> ToolCallResult {
        let envelope = serde_json::json!({
            "toolName": "notes",
            "response": response,
            "downstreamError": null,
        });
        ToolCallResult {
            content: vec![ToolContent::text(envelope.to_string())],
            structured_content: Some(envelope),
            is_error: false,
            meta: None,
        }
    }

    fn http_response(content_type: &str, body: &str) -> serde_json::Value {
        serde_json::json!({
            "statusCode": 200,
            "contentType": content_type,
            "body": body,
            "bodyTruncated": false,
            "json": serde_json::from_str::<serde_json::Value>(body).ok(),
        })
    }

    fn only_text(result: &ResourceReadResult) -> &ResourceTextContents {
        match result.contents.as_slice() {
            [ResourceContents::Text(text)] => text,
            other => panic!("expected one text content, got {other:?}"),
        }
    }

    #[test]
    fn an_http_resource_serves_its_upstream_body_as_its_contents() {
        let answer = http_answer(http_response("text/plain; charset=utf-8", "# Today"));

        let declared = decode_http_resource_result(&answer, "notes://today", Some("text/markdown"))
            .expect("decoded");
        let text = only_text(&declared);
        assert_eq!(text.uri, "notes://today");
        assert_eq!(text.text, "# Today");
        assert_eq!(text.mime_type.as_deref(), Some("text/markdown"));

        let undeclared =
            decode_http_resource_result(&answer, "notes://today", None).expect("decoded");
        assert_eq!(
            only_text(&undeclared).mime_type.as_deref(),
            Some("text/plain; charset=utf-8"),
            "without a declared type the upstream's content type is the resource's"
        );
    }

    #[test]
    fn an_http_resource_serves_a_json_body_as_its_text() {
        // An API's own `contents` field is data, not MCP contents.
        for body in [
            r#"{"items":[1,2]}"#,
            r#"{"contents":[{"id":"a"}],"totalCount":1}"#,
        ] {
            let answer = http_answer(http_response("application/json", body));
            let got = decode_http_resource_result(&answer, "r://items", None).expect("decoded");
            assert_eq!(only_text(&got).text, body);
            assert_eq!(
                only_text(&got).mime_type.as_deref(),
                Some("application/json")
            );
        }
    }

    #[test]
    fn an_http_resource_that_answers_mcp_contents_serves_them_as_they_are() {
        let body = r#"{"contents":[{"uri":"r://logo","blob":"AAEC","mimeType":"image/png"}]}"#;
        let answer = http_answer(http_response("application/json", body));
        let got =
            decode_http_resource_result(&answer, "r://logo", Some("text/plain")).expect("decoded");
        match got.contents.as_slice() {
            [ResourceContents::Blob(blob)] => {
                assert_eq!(blob.uri, "r://logo");
                assert_eq!(blob.blob, "AAEC");
                assert_eq!(blob.mime_type.as_deref(), Some("image/png"));
            }
            other => panic!("expected one blob, got {other:?}"),
        }
    }

    #[test]
    fn an_http_resource_cut_at_its_size_limit_is_refused() {
        let mut response = http_response("text/plain", "# To");
        response["bodyTruncated"] = true.into();
        let err = decode_http_resource_result(&http_answer(response), "notes://today", None)
            .expect_err("a cut body is refused");
        assert!(
            matches!(err, SurfaceDecodeError::MalformedResponse { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_http_resource_whose_body_is_not_utf8_is_refused() {
        let answer = http_answer(http_response("image/png", "\u{FFFD}PNG"));
        let err = decode_http_resource_result(&answer, "r://logo", None)
            .expect_err("a damaged body is refused");
        assert!(
            matches!(err, SurfaceDecodeError::MalformedResponse { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_http_resource_error_answer_is_a_backend_error() {
        let mut answer = http_answer(http_response("text/plain", "down"));
        answer.is_error = true;
        let err = decode_http_resource_result(&answer, "r://a", None).expect_err("an error");
        assert!(
            matches!(err, SurfaceDecodeError::BackendError { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn only_an_http_route_reads_the_answer_envelope() {
        use crate::backends::BackendInvocationRoute;
        let answer = http_answer(http_response("text/plain", "hello"));
        for route in [
            BackendInvocationRoute::NetworkQueryCall {
                profile: "notes".to_owned(),
            },
            BackendInvocationRoute::NetworkJsonCall {
                profile: "notes".to_owned(),
            },
        ] {
            let got =
                decode_binding_resource_result(&route, &answer, "r://a", None).expect("decoded");
            assert_eq!(only_text(&got).text, "hello");
        }
        let mock = BackendInvocationRoute::MockResponse {
            profile: "notes".to_owned(),
        };
        let err = decode_binding_resource_result(&mock, &answer, "r://a", None)
            .expect_err("any other route answers MCP contents");
        assert!(
            matches!(err, SurfaceDecodeError::MalformedResponse { .. }),
            "{err:?}"
        );
    }
}
