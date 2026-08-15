//! MCP JSON-RPC protocol types and message parsing.
//!
//! Defines the wire format for client/server messages, capability
//! negotiation, and protocol version handling per the MCP specification.
//!
//! ## Multi-version architecture
//!
//! The module is organized as a version-aware layout:
//! - [`version`] — `ProtocolVersion` enum + parsing.
//! - [`shared`] — version-agnostic primitives (`ProtocolHandler` trait,
//!   `ProtocolMessage`, pipeline suspension intermediates).
//! - [`registry`] — `ProtocolRegistry` that selects a handler per
//!   inbound request.
//! - `v_<date>` — per-revision wire modules
//!   ([`v_2025_11_25`], [`v_2026_07_28`]).
//!
//! This file re-exports the shared primitives and the current
//! revision's wire types so `crate::protocol::{Type, ...}` resolves to
//! a stable surface.

pub mod registry;
pub mod v_2025_11_25;
pub mod v_2026_07_28;

pub use mcpg_mcp_wire::version;

pub mod shared {
    //! Version-agnostic primitives. The wire half lives in
    //! `mcpg-mcp-wire`; the [`traits`] seam to the runtime stays
    //! here, because it is the one piece of `shared` that is not
    //! wire.
    pub use mcpg_mcp_wire::shared::*;

    pub mod traits;
}

// Re-exports from `shared::*` keep the surface of
// `crate::protocol::{Type,...}` stable across the per-version
// layout, so callers reach the version-agnostic types without
// naming a specific wire module.
pub use shared::content::{ContentAnnotations, EmbeddedResource, Icon, ToolContent};
pub use shared::error::{
    HEADER_MISMATCH_CODE, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
    METHOD_NOT_FOUND_CODE, MISSING_REQUIRED_CLIENT_CAPABILITY_CODE, PARSE_ERROR_CODE,
    PAYMENT_REQUIRED_CODE, PAYMENT_VERIFICATION_FAILED_CODE, ProtocolError,
    UNSUPPORTED_PROTOCOL_VERSION_CODE,
};
pub use shared::jsonrpc::{
    ClientMessage, JSONRPC_VERSION, JsonRpcError, JsonRpcErrorBody, JsonRpcNotification,
    JsonRpcRequest, JsonRpcResponse, JsonRpcSuccess, ProtocolHttpResponse, ProtocolResponse,
    parse_client_message,
};
// Version-specific constants + lifecycle/capability negotiation types
// live under `v_2025_11_25::wire`. The re-exports keep their bare
// names accessible via `crate::protocol::Type`.
pub use v_2025_11_25::wire::common::{
    CONTENT_TOO_LARGE_CODE, CancelledNotificationParams, EmptyResult, GUARDRAIL_DENIED_CODE,
    GUARDRAIL_SERVICE_ERROR_CODE, ListChangedNotification, ListParams, ProgressNotification,
    ProgressParams, ServerJsonRpcRequest,
};
pub use v_2025_11_25::wire::completion::{
    CompletionArgument, CompletionCompleteParams, CompletionContext, CompletionReference,
    CompletionResult, CompletionValues,
};
pub use v_2025_11_25::wire::elicitation::{
    ELICITATION_NOT_SUPPORTED_CODE, ElicitationAction, ElicitationCompleteNotification,
    ElicitationCompleteParams, ElicitationCreateParams, URL_ELICITATION_REQUIRED_CODE,
};
pub use v_2025_11_25::wire::lifecycle::{
    CapabilityFlag, ClientCapabilities, ClientElicitationCapability, ClientRootsCapability,
    ClientSamplingCapability, ClientTaskElicitationCapability, ClientTaskRequestsCapability,
    ClientTaskRootsCapability, ClientTaskSamplingCapability, ClientTasksCapability,
    ImplementationInfo, InitializeParams, InitializeResult, ListCapability, ResourceCapability,
    ServerCapabilities, ServerTaskRequestsCapability, ServerTaskToolsCapability, TasksCapability,
};
pub use v_2025_11_25::wire::logging::{
    LoggingLevel, LoggingMessageNotification, LoggingMessageParams, LoggingSetLevelParams,
};
pub use v_2025_11_25::wire::operations::{
    CapabilityOperation, LifecycleOperation, LoggingOperation, ProtocolOperation, TaskOperation,
};
pub use v_2025_11_25::wire::prompts::{
    PromptGetParams, PromptGetResult, PromptMessage, PromptMessageContent, PromptsListResult,
};
pub use v_2025_11_25::wire::resources::{
    BlobResourceContents, ResourceContents, ResourceReadParams, ResourceReadResult,
    ResourceSubscribeParams, ResourceTemplate, ResourceTemplatesListResult, ResourceTextContents,
    ResourceUpdatedNotification, ResourceUpdatedParams, ResourcesListResult,
};
pub use v_2025_11_25::wire::routing::map_client_message_to_operation;
pub use v_2025_11_25::wire::sampling::{
    SamplingCreateMessageParams, SamplingIncludeContext, SamplingMessage, SamplingMessageContent,
};
pub use v_2025_11_25::wire::tasks::{
    CreateTaskResult, MODEL_IMMEDIATE_RESPONSE_META_KEY, RELATED_TASK_META_KEY, Task,
    TaskAugmentParams, TaskCancelParams, TaskGetParams, TaskResultParams, TaskStatus,
    TaskStatusNotification, TaskStatusNotificationParams, TasksListParams, TasksListResult,
    related_task_meta,
};
pub use v_2025_11_25::wire::tools::{ToolCallParams, ToolCallResult, ToolsListResult};
pub use v_2025_11_25::wire::{
    DEFAULT_SAMPLING_MAX_TOKENS, LEGACY_DEFAULT_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSIONS,
    PROTOCOL_VERSION_HEADER, SESSION_ID_HEADER, SUPPORTED_PROTOCOL_VERSION,
};

// This module no longer holds any inline wire types, validators,
// parser, router, or tests of its own — every such item now lives
// under `shared/` or `v_2025_11_25/wire/`. The remaining content
// above is purely module declarations and `pub use` re-exports
// that preserve the historical surface of
// `crate::protocol::{Type, fn, …}` for existing imports across the
// gateway, transports, and runtime.
