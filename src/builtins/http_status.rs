//! Built-in `http_route` plugin — `dev.mcpg.builtin.http.status`.
//!
//! Reference implementation of the `http_route` entity kind. Exposes
//! a minimal JSON status surface under `/plugins/dev.mcpg.builtin.http.
//! status/status` that operators (and the integration tests) hit to
//! confirm the axum dispatcher, registry lookup, and plugin handle
//! path all hold together end-to-end.
//!
//! Two routes:
//!   - `GET /` — returns `{"ok": true, "service": ..., "version": ...}`.
//!   - `GET /deep` — same shape plus an `uptime_secs` field. Added
//!     so the test suite exercises `:name`-less path matching with
//!     more than one path segment.
//!
//! Scope caveats (intentional — kept deliberately small):
//!   - No per-plugin config surface. Operator config plumbing for
//!     `http_route` is deferred to a later iteration.
//!   - No streaming. The dispatcher's streaming path is exercised by
//!     dispatcher unit tests; burning a built-in on it would add code
//!     without moving real coverage.
//!   - No `requires_identity`. The built-in is always anonymous — the
//!     gateway's real `/healthz` sits behind the same policy.

use std::sync::Arc;
use std::time::Instant;

use mcpg_plugin_protocol::http_route::{HttpRoute, HttpRouteRequest, HttpRouteResponse, RouteSpec};
use mcpg_plugin_protocol::{PluginClass, PluginManifest};

/// Embedded descriptor shipped next to the source. `FirstPartyRegistrar`
/// parses this at registration time and cross-checks against the
/// in-code `PluginManifest`.
pub const DESCRIPTOR_YAML: &str = r#"
schema: mcpg.dev/plugin/v1
id: dev.mcpg.builtin.http.status
name: Built-in HTTP Status
description: |
  Gateway-bundled proof-point for the http_route entity kind. Exposes
  a JSON status endpoint mounted at /plugins/dev.mcpg.builtin.http.
  status/status for operator smoke tests and integration
  tests. Ships as static-firstparty-v1 — never distributed as OCI.
class: http_route
runtime: static-firstparty-v1
protocol_version: "1.0"
required_capabilities: []
"#;

/// Entity name the plugin registers under. Baked in here (not
/// operator-configurable) because operator config plumbing for
/// `http_route` is deferred to a later iteration.
pub const ENTITY_NAME: &str = "status";

/// Built-in status plugin.
pub struct HttpStatusPlugin {
    manifest: PluginManifest,
    service_name: String,
    service_version: String,
    started_at: Instant,
}

impl HttpStatusPlugin {
    /// Build a new instance. `service_name` + `service_version` are
    /// echoed in every response body — callers typically pass the
    /// gateway's own `runtime.service_name` / `service_version` so
    /// the built-in mirrors the gateway's identity.
    #[must_use]
    pub fn new(service_name: impl Into<String>, service_version: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            manifest: PluginManifest {
                id: "dev.mcpg.builtin.http.status".into(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                name: "Built-in HTTP Status".into(),
                plugin_class: PluginClass::HttpRoute,
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
            service_name: service_name.into(),
            service_version: service_version.into(),
            started_at: Instant::now(),
        })
    }

    fn status_body(&self, deep: bool) -> serde_json::Value {
        let mut body = serde_json::json!({
            "ok": true,
            "service": self.service_name,
            "version": self.service_version,
            "plugin_id": self.manifest.id,
        });
        if deep {
            body["uptime_secs"] = self.started_at.elapsed().as_secs().into();
            body["checks"] = serde_json::json!({ "http_route_dispatcher": "pass" });
        }
        body
    }
}

#[mcpg_plugin_protocol::async_trait]
impl HttpRoute for HttpStatusPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn routes(&self) -> Vec<RouteSpec> {
        vec![
            RouteSpec {
                method: "GET".into(),
                path: "/".into(),
                requires_identity: false,
                streaming: false,
                max_body_bytes: None,
            },
            RouteSpec {
                method: "GET".into(),
                path: "/deep".into(),
                requires_identity: false,
                streaming: false,
                max_body_bytes: None,
            },
        ]
    }

    async fn handle(&self, req: HttpRouteRequest) -> HttpRouteResponse {
        // The dispatcher only forwards requests that matched one of
        // our specs, so the only branching we need is shallow-vs-deep.
        let deep = req.full_path.ends_with("/deep") || req.full_path.ends_with("/deep/");
        HttpRouteResponse::ok_json(&self.status_body(deep))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::http_route::HttpBody;
    use std::collections::BTreeMap;

    fn request(path: &str) -> HttpRouteRequest {
        HttpRouteRequest {
            method: "GET".into(),
            full_path: path.into(),
            path_params: BTreeMap::new(),
            query: vec![],
            headers: vec![],
            body: bytes::Bytes::new(),
            identity: None,
            request_id: "r1".into(),
            remote_addr: None,
        }
    }

    #[tokio::test]
    async fn shallow_status_returns_ok_json() {
        let plugin = HttpStatusPlugin::new("mcpg", "0.1.0");
        let resp = plugin
            .handle(request("/plugins/dev.mcpg.builtin.http.status/status/"))
            .await;
        assert_eq!(resp.status, 200);
        let HttpBody::Bytes(body) = resp.body else {
            panic!("expected bytes body");
        };
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["service"], "mcpg");
        assert_eq!(json["version"], "0.1.0");
        assert!(json.get("uptime_secs").is_none());
    }

    #[tokio::test]
    async fn deep_status_includes_uptime() {
        let plugin = HttpStatusPlugin::new("mcpg", "0.1.0");
        let resp = plugin
            .handle(request("/plugins/dev.mcpg.builtin.http.status/status/deep"))
            .await;
        assert_eq!(resp.status, 200);
        let HttpBody::Bytes(body) = resp.body else {
            panic!("expected bytes body");
        };
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["uptime_secs"].is_number());
        assert_eq!(json["checks"]["http_route_dispatcher"], "pass");
    }

    #[test]
    fn manifest_class_is_http_route() {
        let plugin = HttpStatusPlugin::new("mcpg", "0.1.0");
        assert_eq!(plugin.manifest().plugin_class, PluginClass::HttpRoute);
        assert_eq!(plugin.routes().len(), 2);
    }

    #[test]
    fn descriptor_yaml_parses_and_matches_manifest() {
        let d: mcpg_plugin_protocol::PluginDescriptor =
            serde_yaml::from_str(DESCRIPTOR_YAML).expect("descriptor parses");
        assert!(d.is_current_schema());
        assert_eq!(d.id, "dev.mcpg.builtin.http.status");
        assert_eq!(d.class, PluginClass::HttpRoute);
    }
}
