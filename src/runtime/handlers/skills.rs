//! The SEP-2640 Skills extension: `skills/list`, `skills/get` and
//! `resources/directory/read`. `resources/read` of a skill file is served
//! in `capabilities_list.rs`, beside every other resource read.

use super::super::*;
use crate::protocol::shared::caching::{CacheScope, DEFAULT_LIST_TTL_MS, RESULT_TYPE_COMPLETE};
use crate::protocol::shared::skills::{
    GetSkillResult, ListSkillsResult, ReadDirectoryResult, SkillsOperation, capability_value,
};
use crate::runtime::skills::{SkillCatalog, SkillsWire};

impl GatewayRuntime {
    /// Install the skills this runtime serves.
    pub fn set_skills(&mut self, catalog: Option<SkillCatalog>) {
        self.skills = catalog.map(Arc::new);
    }

    /// Whether `uri` is a skill file this runtime serves.
    pub(crate) fn serves_skill_file(&self, uri: &str) -> bool {
        self.skills.as_ref().is_some_and(|c| c.file(uri).is_some())
    }

    /// The value declared under `io.modelcontextprotocol/skills`, when
    /// skills are served.
    pub(crate) fn skills_capability(&self) -> Option<serde_json::Value> {
        self.skills
            .as_ref()
            .map(|catalog| capability_value(catalog.directory_read()))
    }

    /// Per-caller visibility of a skill file or folder, decided as a
    /// `resources/read` of that URI is.
    pub(crate) fn skill_resource_is_visible(
        &self,
        request_context: &RequestContext,
        uri: &str,
    ) -> bool {
        self.surface_is_visible(request_context, uri, PolicyRoute::for_skill())
    }

    pub(crate) async fn handle_skills_operation(
        &self,
        operation: SkillsOperation,
        request_context: &RequestContext,
        wire: SkillsWire,
    ) -> ProtocolHttpResponse {
        let request_id = operation.request_id().clone();
        let method = operation.method();
        let Some(catalog) = self.skills.clone() else {
            return skills_error(
                wire.not_found_status(),
                request_id,
                -32601,
                format!("Method not found: {method}"),
            );
        };
        if method == crate::protocol::shared::skills::METHOD_READ_DIRECTORY
            && !catalog.directory_read()
        {
            return skills_error(
                wire.not_found_status(),
                request_id,
                -32601,
                format!("Method not found: {method}"),
            );
        }
        if wire == SkillsWire::Legacy
            && let Err(error) = request_context.load_session_cached(&*self.session_store, true)
        {
            return self.map_session_error_to_protocol_response(error, Some(request_id));
        }
        let result_type = (wire == SkillsWire::Modern).then(|| RESULT_TYPE_COMPLETE.to_owned());
        metrics::counter!("mcpg_skills_requests_total", "method" => method).increment(1);

        match operation {
            SkillsOperation::InvalidParams { message, .. } => {
                skills_error(200, request_id, -32602, message)
            }
            SkillsOperation::List { params, .. } => {
                if !self.cursor_is_valid(params.cursor.as_deref(), request_context) {
                    return skills_error(
                        200,
                        request_id,
                        -32602,
                        "invalid pagination cursor".to_owned(),
                    );
                }
                let visible: Vec<_> = catalog
                    .skills()
                    .iter()
                    .filter(|skill| {
                        self.skill_resource_is_visible(request_context, &skill.entry.uri)
                    })
                    .map(|skill| skill.entry.clone())
                    .collect();
                let (page, next_cursor) = paginate_list_bound(
                    &visible,
                    params.cursor.as_deref(),
                    Some(&self.cursor_binding_key(request_context)),
                    self.list_page_size(),
                );
                let event = mcpg_plugin_host::audit_events::list_call_event(
                    plugin_identity_from_request(request_context),
                    request_context.request_id.as_str(),
                    request_context.session_id.as_deref(),
                    "skill",
                    page.len() as u64,
                    transport_label(&request_context.transport),
                );
                let _ = self.plugin_registry.emit_audit_event(&event).await;
                skills_success(
                    request_id,
                    &ListSkillsResult {
                        result_type,
                        skills: page,
                        next_cursor,
                        ttl_ms: Some(DEFAULT_LIST_TTL_MS),
                        // Filtered per caller, like `resources/list`.
                        cache_scope: Some(cache_scope_label(CacheScope::Private)),
                    },
                )
            }
            SkillsOperation::Get { params, .. } => {
                // An unknown skill and one this caller may not see answer
                // alike, so the answer does not disclose which it is.
                match catalog
                    .skill(&params.uri)
                    .filter(|_| self.skill_resource_is_visible(request_context, &params.uri))
                {
                    Some(skill) => skills_success(
                        request_id,
                        &GetSkillResult {
                            result_type,
                            skill: skill.entry.clone(),
                        },
                    ),
                    None => skills_error(
                        200,
                        request_id,
                        -32602,
                        format!("Unknown skill: {}", params.uri),
                    ),
                }
            }
            SkillsOperation::ReadDirectory { params, .. } => {
                let Some(children) = catalog
                    .directory(&params.uri)
                    .filter(|_| self.skill_resource_is_visible(request_context, &params.uri))
                else {
                    return skills_error(
                        200,
                        request_id,
                        -32602,
                        format!("Not a directory resource: {}", params.uri),
                    );
                };
                if !self.cursor_is_valid(params.cursor.as_deref(), request_context) {
                    return skills_error(
                        200,
                        request_id,
                        -32602,
                        "invalid pagination cursor".to_owned(),
                    );
                }
                let visible: Vec<crate::backends::ResourceDescriptor> = children
                    .iter()
                    .filter(|child| self.skill_resource_is_visible(request_context, &child.uri))
                    .map(|child| crate::backends::ResourceDescriptor {
                        uri: child.uri.clone(),
                        name: child.name.clone(),
                        title: None,
                        description: None,
                        mime_type: Some(child.mime_type.clone()),
                        size: child.size,
                        icons: None,
                        annotations: None,
                        meta: None,
                    })
                    .collect();
                let (page, next_cursor) = paginate_list_bound(
                    &visible,
                    params.cursor.as_deref(),
                    Some(&self.cursor_binding_key(request_context)),
                    self.list_page_size(),
                );
                skills_success(
                    request_id,
                    &ReadDirectoryResult {
                        result_type,
                        resources: page,
                        next_cursor,
                    },
                )
            }
        }
    }

    /// The `SKILL.md` of every skill, as `resources/list` entries.
    pub(crate) fn skill_resource_descriptors(&self) -> Vec<crate::backends::ResourceDescriptor> {
        let Some(catalog) = self.skills.as_ref().filter(|c| c.list_as_resources()) else {
            return Vec::new();
        };
        catalog
            .skills()
            .iter()
            .map(|skill| crate::backends::ResourceDescriptor {
                uri: skill.entry.uri.clone(),
                name: skill.name.clone(),
                title: None,
                description: Some(skill.description.clone()),
                mime_type: Some(crate::protocol::shared::skills::SKILL_MIME_TYPE.to_owned()),
                size: Some(skill.skill_file_size),
                icons: None,
                annotations: None,
                meta: None,
            })
            .collect()
    }

    /// `resources/read` of a served skill file, after the same pre-dispatch
    /// gate every resource read takes. `None` when `uri` is not one.
    pub(crate) async fn read_skill_file(
        &self,
        uri: &str,
        request_id: &serde_json::Value,
        request_context: &RequestContext,
    ) -> Option<ProtocolHttpResponse> {
        let file = self.skills.as_ref()?.file(uri)?.clone();
        let audit_ctx = mcpg_plugin_protocol::PluginContext {
            request_id: request_context.request_id.as_str().to_owned(),
            session_id: request_context.session_id.clone(),
            tool_name: uri.to_owned(),
            identity: plugin_identity_from_request(request_context),
            transport: transport_label(&request_context.transport).to_owned(),
            surface: "resource".to_owned(),
        };
        if let Err(gate_response) = self
            .evaluate_surface_gate(
                "resource",
                "resource.read.pre",
                uri,
                PolicyRoute::for_skill(),
                &serde_json::json!({ "uri": uri }),
                request_context,
                request_id,
            )
            .await
        {
            let event = mcpg_plugin_host::audit_events::resource_read_denied_event(
                &audit_ctx,
                uri,
                "surface_gate",
            );
            let _ = self.plugin_registry.emit_audit_event(&event).await;
            return Some(gate_response);
        }
        let content = match std::str::from_utf8(&file.bytes) {
            Ok(text) => ResourceContents::Text(ResourceTextContents {
                uri: file.uri.clone(),
                mime_type: Some(file.mime_type.clone()),
                text: text.to_owned(),
                meta: None,
            }),
            Err(_) => {
                use base64::Engine as _;
                ResourceContents::Blob(BlobResourceContents {
                    uri: file.uri.clone(),
                    mime_type: Some(file.mime_type.clone()),
                    blob: base64::engine::general_purpose::STANDARD.encode(&file.bytes),
                    meta: None,
                })
            }
        };
        let event = mcpg_plugin_host::audit_events::resource_read_success_event(
            &audit_ctx,
            uri,
            file.bytes.len() as u64,
        );
        let _ = self.plugin_registry.emit_audit_event(&event).await;
        metrics::counter!("mcpg_skill_file_reads_total").increment(1);
        let result = ResourceReadResult {
            contents: vec![content],
            ttl_ms: Some(crate::protocol::shared::caching::DEFAULT_READ_TTL_MS),
            cache_scope: Some(CacheScope::Private),
            // The digest names these exact bytes.
            cache_token: Some(file.digest.clone()),
        };
        Some(ProtocolHttpResponse {
            http_status: 200,
            session_id_header: None,
            response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
                jsonrpc: JSONRPC_VERSION,
                id: request_id.clone(),
                result: serde_json::to_value(result).expect("skill read result serialized"),
            }),
        })
    }
}

fn cache_scope_label(scope: CacheScope) -> String {
    serde_json::to_value(scope)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "private".to_owned())
}

fn skills_success<T: serde::Serialize>(
    request_id: serde_json::Value,
    result: &T,
) -> ProtocolHttpResponse {
    ProtocolHttpResponse {
        http_status: 200,
        session_id_header: None,
        response: ProtocolResponse::JsonRpcSuccess(JsonRpcSuccess {
            jsonrpc: JSONRPC_VERSION,
            id: request_id,
            result: serde_json::to_value(result).expect("skills result serialized"),
        }),
    }
}

fn skills_error(
    http_status: u16,
    request_id: serde_json::Value,
    code: i32,
    message: String,
) -> ProtocolHttpResponse {
    protocol_http_error(http_status, Some(request_id), code, message, None)
}
