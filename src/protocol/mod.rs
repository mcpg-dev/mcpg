//! MCP JSON-RPC protocol surface of the gateway: MCP `2026-07-28`.
//!
//! The wire types live in `mcpg-mcp-wire`. This module re-exports them,
//! so the gateway names them as `crate::protocol::Type`, and holds:
//! - [`negotiate`] — the protocol-version check every request passes
//!   before dispatch.
//! - [`Handler`] — header validation, parsing and dispatch of one request.
//! - [`v_2026_07_28`] — the wire re-export, the extensions and the
//!   per-method dispatch arms.

pub mod negotiation;
pub mod v_2026_07_28;

pub mod shared {
    //! Wire primitives shared by every method, from `mcpg-mcp-wire`.
    pub use mcpg_mcp_wire::shared::*;
}

pub use negotiation::{ProtocolNegotiationError, negotiate};
pub use v_2026_07_28::handler::{Handler, StreamPlan};

pub use mcpg_mcp_wire::{
    BlobResourceContents, CancelledNotificationParams, CapabilityFlag, ClientCapabilities,
    ClientElicitationCapability, ClientMessage, ClientRootsCapability, ClientSamplingCapability,
    CompletionArgument, CompletionCompleteParams, CompletionContext, CompletionReference,
    CompletionResult, CompletionValues, ContentAnnotations, DEFAULT_SAMPLING_MAX_TOKENS,
    ElicitationCreateParams, EmbeddedResource, HEADER_MISMATCH_CODE, INTERNAL_ERROR_CODE,
    INVALID_PARAMS_CODE, INVALID_REQUEST_CODE, Icon, JSONRPC_VERSION, JsonRpcError,
    JsonRpcErrorBody, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, JsonRpcSuccess,
    ListChangedNotification, METHOD_NOT_FOUND_CODE, MISSING_REQUIRED_CLIENT_CAPABILITY_CODE,
    PARSE_ERROR_CODE, PAYMENT_REQUIRED_CODE, PAYMENT_VERIFICATION_FAILED_CODE,
    PROTOCOL_VERSION_HEADER, ProgressNotification, ProgressParams, PromptGetParams,
    PromptGetResult, PromptMessage, PromptMessageContent, ProtocolError, ProtocolHttpResponse,
    ProtocolResponse, ResourceContents, ResourceReadParams, ResourceReadResult, ResourceTemplate,
    ResourceTextContents, ResourceUpdatedNotification, ResourceUpdatedParams,
    SUPPORTED_PROTOCOL_VERSION, SamplingCreateMessageParams, SamplingIncludeContext,
    SamplingMessage, SamplingMessageContent, ServerJsonRpcRequest, Task, TaskStatus,
    ToolCallParams, ToolCallResult, ToolContent, UNSUPPORTED_PROTOCOL_VERSION_CODE,
    parse_client_message,
};
