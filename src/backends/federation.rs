use super::capability_registry::{
    CompiledResourceTemplate, RegisteredPrompt, RegisteredResource, RegisteredTool,
    compile_resource_template,
};
use super::*;

/// A federated tool the `FederationEngine` contributes to the capability
/// overlay: the MCP descriptor the client sees plus the route that
/// dispatches it back to the owning upstream.
#[derive(Debug, Clone)]
pub struct FederatedTool {
    pub descriptor: ToolDescriptor,
    pub route: BackendInvocationRoute,
}

/// A federated resource the `FederationEngine` contributes to the
/// overlay: the (prefixed) descriptor the client sees + the route that
/// reads it back from the owning upstream.
#[derive(Debug, Clone)]
pub struct FederatedResource {
    pub descriptor: ResourceDescriptor,
    pub route: ResourceRoute,
}

/// A federated prompt the `FederationEngine` contributes to the overlay:
/// the (prefixed) descriptor the client sees + the route that fetches it
/// from the owning upstream.
#[derive(Debug, Clone)]
pub struct FederatedPrompt {
    pub descriptor: PromptDescriptor,
    pub route: PromptRoute,
}

/// A federated resource *template* the `FederationEngine` contributes to
/// the overlay. Unlike an exact resource, the concrete URI a client reads
/// is only known at read time (the client expands the template), so the
/// route is reconstructed then: a matched URI is de-prefixed back to the
/// upstream URI and dispatched via [`ResourceRoute::Federated`].
#[derive(Debug, Clone)]
pub struct FederatedResourceTemplate {
    /// Prefixed template descriptor the client sees in `resources/templates/list`.
    pub descriptor: crate::protocol::ResourceTemplate,
    /// Owning federation source (for dispatch).
    pub source: String,
    /// URI prefix to strip from a matched concrete URI → upstream URI.
    pub prefix: String,
}

/// Compiled federated template matcher held inside the overlay: matches an
/// incoming (prefixed) URI and, on a hit, yields the source + prefix needed
/// to reconstruct the upstream read.
#[derive(Debug, Clone)]
pub(crate) struct CompiledFederatedTemplate {
    pub(crate) matcher: CompiledResourceTemplate,
    pub(crate) source: String,
    pub(crate) prefix: String,
}

/// Runtime-mutable overlay of federated capabilities.
/// Built by the `FederationEngine` from imported upstream capabilities and
/// swapped atomically into the [`CapabilityRegistry`]. Native bindings are
/// never in here.
#[derive(Debug, Default)]
pub struct FederatedCatalog {
    pub(crate) tools: Vec<RegisteredTool>,
    pub(crate) resources: Vec<RegisteredResource>,
    /// Template descriptors for `resources/templates/list`.
    pub(crate) resource_templates: Vec<crate::protocol::ResourceTemplate>,
    /// Compiled template matchers for `resources/read` URI routing.
    pub(crate) resource_template_routes: Vec<CompiledFederatedTemplate>,
    pub(crate) prompts: Vec<RegisteredPrompt>,
}

impl FederatedCatalog {
    /// Build an overlay from the engine's federated tools + resources +
    /// resource templates + prompts. Template matchers are compiled here
    /// from the (already-prefixed) `uriTemplate`; a template that fails to
    /// compile still lists but won't route (logged, never panics).
    #[must_use]
    pub fn from_parts(
        tools: Vec<FederatedTool>,
        resources: Vec<FederatedResource>,
        resource_templates: Vec<FederatedResourceTemplate>,
        prompts: Vec<FederatedPrompt>,
    ) -> Self {
        let mut template_descriptors = Vec::with_capacity(resource_templates.len());
        let mut resource_template_routes = Vec::with_capacity(resource_templates.len());
        for t in resource_templates {
            if let Some(matcher) = compile_resource_template(&t.source, &t.descriptor.uri_template)
            {
                resource_template_routes.push(CompiledFederatedTemplate {
                    matcher,
                    source: t.source.clone(),
                    prefix: t.prefix.clone(),
                });
            } else {
                tracing::warn!(
                    source = %t.source,
                    template = %t.descriptor.uri_template,
                    "federated resource template did not compile to a matcher; it lists but reads won't route"
                );
            }
            template_descriptors.push(t.descriptor);
        }
        Self {
            tools: tools
                .into_iter()
                .map(|t| RegisteredTool {
                    descriptor: t.descriptor,
                    route: t.route,
                })
                .collect(),
            resources: resources
                .into_iter()
                .map(|r| RegisteredResource {
                    descriptor: r.descriptor,
                    route: r.route,
                    app_url_pattern: None,
                })
                .collect(),
            resource_templates: template_descriptors,
            resource_template_routes,
            prompts: prompts
                .into_iter()
                .map(|p| RegisteredPrompt {
                    descriptor: p.descriptor,
                    route: p.route,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len() + self.resources.len() + self.resource_templates.len() + self.prompts.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
            && self.resources.is_empty()
            && self.resource_templates.is_empty()
            && self.prompts.is_empty()
    }
}
