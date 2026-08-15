//! MCP Apps (SEP-1865 — `io.modelcontextprotocol/ui`) config.
//!
//! The `apps:` block under `mcp.configurations`: capability
//! advertisement, the tighten-only CSP / permission policy layer, and
//! the gateway-authored templated-apps registry (`ui://mcpg/<id>`).

use anyhow::Result;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// MCP Apps (SEP-1865 — `io.modelcontextprotocol/ui`)
// ---------------------------------------------------------------------------

/// `apps:` config — SEP-1865 MCP Apps support.
///
/// MCP Apps lets a server attach an interactive HTML UI to a tool. The
/// `ui/*` postMessage protocol runs host↔iframe and never reaches the
/// gateway; MCPG's role is passthrough of `_meta.ui`, capability
/// advertisement (both downstream to clients and upstream to federated
/// servers), federation `resourceUri` rewriting, and a tighten-only
/// CSP/permission policy layer.
///
/// Off by default. When `enabled: false`, MCPG omits the
/// `io.modelcontextprotocol/ui` extension from its capability
/// advertisement and applies no policy — but `_meta.ui` still
/// round-trips on tool/resource descriptors (passthrough is wire-shape,
/// not capability-gated, so a client with a cached template keeps
/// working). When `enabled: true`, advertisement lights up and the
/// `csp_policy` / `allowed_permissions` / `allowed_domains` clamps below
/// are enforced on egress.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppsConfig {
    /// Master switch for DOWNSTREAM advertisement + egress policy.
    /// Default `false` (opt-in).
    #[serde(default)]
    pub enabled: bool,

    /// Advertise the Apps capability on MCPG's OUTGOING
    /// (client→upstream) `initialize` so federated servers emit their
    /// UI-enabled tools. A spec-compliant upstream checks the client's
    /// `io.modelcontextprotocol/ui` capability before registering UI
    /// tools — omit this and such an upstream withholds every UI tool.
    /// `None` ⇒ inherit `enabled`. Set `true` explicitly to pull UI
    /// tools from upstreams while still withholding the capability from
    /// your own clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federate_upstream: Option<bool>,

    /// Reject (vs sanitize) an upstream response whose `_meta.ui`
    /// escaped the policy below — a domain/permission/CSP entry outside
    /// the operator allow-list. Default `false` (permissive: narrow +
    /// log, never reject).
    #[serde(default)]
    pub strict: bool,

    /// CSP upper bound. Each axis is **intersected** (never unioned)
    /// with the upstream's declared `_meta.ui.csp`. `["*"]` on an axis
    /// imposes no bound on that axis (upstream passes through). An
    /// *omitted* axis on the upstream is left omitted (the host applies
    /// its restrictive default — `frame-src 'none'` / `base-uri
    /// 'self'`); policy never materializes an absent axis.
    #[serde(default)]
    pub csp_policy: AppsCspPolicy,

    /// iframe permissions MCPG will let through; any
    /// `_meta.ui.permissions` key outside this list is stripped on
    /// egress. Default: all four standard permissions.
    #[serde(default = "AppsConfig::default_allowed_permissions")]
    pub allowed_permissions: Vec<AppsPermission>,

    /// If set, a `_meta.ui.domain` outside this list is dropped (the
    /// host falls back to its default sandbox origin); in `strict` mode
    /// the whole response is rejected instead. `None` ⇒ any domain
    /// allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,

    /// Gateway-authored templated apps. Each entry mints a
    /// `ui://mcpg/<id>` resource whose behavior is driven by this
    /// config; the gateway ships the HTML, the operator supplies only
    /// the binding. Empty ⇒ no authored apps (pure proxy posture).
    /// Non-empty requires `enabled: true`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registry: Vec<GatewayAppConfig>,
}

/// The CSP-axis allow-lists. Defaults mirror a sensible middlebox
/// posture: no bound on what the app may fetch/connect/redirect to
/// (`["*"]`), but frame embedding and `<base>` pinned to `self`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppsCspPolicy {
    #[serde(default = "AppsCspPolicy::default_any")]
    pub connect_domains: Vec<String>,
    #[serde(default = "AppsCspPolicy::default_any")]
    pub resource_domains: Vec<String>,
    #[serde(default = "AppsCspPolicy::default_self")]
    pub frame_domains: Vec<String>,
    #[serde(default = "AppsCspPolicy::default_self")]
    pub base_uri_domains: Vec<String>,
    /// Allow-list for `openExternal` redirect targets. Clamps only the
    /// OpenAI `openai/widgetCSP.redirect_domains` alias (there is no
    /// `_meta.ui.csp` axis for it). Default `["*"]` ⇒ no bound.
    #[serde(default = "AppsCspPolicy::default_any")]
    pub redirect_domains: Vec<String>,
}

/// A standard iframe permission. Serialized snake_case in config;
/// maps to the camelCase `_meta.ui.permissions` key on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppsPermission {
    Camera,
    Microphone,
    Geolocation,
    ClipboardWrite,
}

impl AppsPermission {
    /// The camelCase key this permission carries on `_meta.ui.permissions`.
    pub fn wire_key(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Geolocation => "geolocation",
            Self::ClipboardWrite => "clipboardWrite",
        }
    }
}

impl Default for AppsCspPolicy {
    fn default() -> Self {
        Self {
            connect_domains: Self::default_any(),
            resource_domains: Self::default_any(),
            frame_domains: Self::default_self(),
            base_uri_domains: Self::default_self(),
            redirect_domains: Self::default_any(),
        }
    }
}

impl AppsCspPolicy {
    fn default_any() -> Vec<String> {
        vec!["*".to_owned()]
    }
    fn default_self() -> Vec<String> {
        vec!["self".to_owned()]
    }
}

impl Default for AppsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            federate_upstream: None,
            strict: false,
            csp_policy: AppsCspPolicy::default(),
            allowed_permissions: Self::default_allowed_permissions(),
            allowed_domains: None,
            registry: Vec::new(),
        }
    }
}

impl AppsConfig {
    fn default_allowed_permissions() -> Vec<AppsPermission> {
        vec![
            AppsPermission::Camera,
            AppsPermission::Microphone,
            AppsPermission::Geolocation,
            AppsPermission::ClipboardWrite,
        ]
    }

    /// Whether MCPG advertises the Apps capability on its outgoing
    /// (client→upstream) `initialize`. Inherits `enabled` when
    /// `federate_upstream` is unset.
    pub fn federate_upstream_enabled(&self) -> bool {
        self.federate_upstream.unwrap_or(self.enabled)
    }

    /// Compile the operator policy into the version-agnostic
    /// [`crate::protocol::shared::apps::AppsPolicy`] used on egress.
    pub fn compiled_policy(&self) -> crate::protocol::shared::apps::AppsPolicy {
        crate::protocol::shared::apps::AppsPolicy {
            connect_domains: self.csp_policy.connect_domains.clone(),
            resource_domains: self.csp_policy.resource_domains.clone(),
            frame_domains: self.csp_policy.frame_domains.clone(),
            base_uri_domains: self.csp_policy.base_uri_domains.clone(),
            redirect_domains: self.csp_policy.redirect_domains.clone(),
            allowed_permissions: self
                .allowed_permissions
                .iter()
                .map(|p| p.wire_key().to_owned())
                .collect(),
            allowed_domains: self.allowed_domains.clone(),
            strict: self.strict,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if let Some(domains) = &self.allowed_domains
            && domains.is_empty()
        {
            anyhow::bail!(
                "apps.allowed_domains is set but empty — this would drop EVERY _meta.ui.domain. \
                 Omit the field to allow any domain, or list the permitted origins."
            );
        }
        self.validate_registry()?;
        Ok(())
    }

    /// Structural validation of the templated-app registry.
    /// Tool-existence is cross-checked later, post-catalog-build
    /// (the catalog is not available at this layer); here we enforce the
    /// shape, the `ui://mcpg/<id>` authority grammar, kind/field
    /// compatibility, and the credential firewall.
    fn validate_registry(&self) -> Result<()> {
        if self.registry.is_empty() {
            return Ok(());
        }
        // The capability must be lit for authored apps to be advertised.
        if !self.enabled {
            anyhow::bail!(
                "apps.registry is non-empty but apps.enabled is false — set enabled: true \
                 to advertise and serve the authored apps."
            );
        }
        const MAX_APPS: usize = 256;
        if self.registry.len() > MAX_APPS {
            anyhow::bail!(
                "apps.registry has {} apps (max {MAX_APPS}) — each compiles a resident HTML body",
                self.registry.len()
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for app in &self.registry {
            // `id` becomes the `ui://mcpg/<id>` authority path segment.
            if !is_valid_app_id(&app.id) {
                anyhow::bail!(
                    "apps.registry: invalid app id {:?} — must match [a-z0-9] then [a-z0-9-]*",
                    app.id
                );
            }
            if !seen.insert(app.id.as_str()) {
                anyhow::bail!("apps.registry: duplicate app id {:?}", app.id);
            }
            app.validate()
                .map_err(|e| anyhow::anyhow!("apps.registry[{}]: {e}", app.id))?;
            if self.strict {
                self.check_app_within_policy(app)?;
            }
        }
        Ok(())
    }

    /// In `strict` mode, reject an authored app whose declared CSP axes or
    /// permissions exceed the operator egress policy. (Egress still clamps
    /// these regardless — this surfaces the operator's own misconfiguration
    /// up front instead of silently narrowing, mirroring how strict rejects
    /// an over-broad upstream `_meta.ui`.)
    fn check_app_within_policy(&self, app: &GatewayAppConfig) -> Result<()> {
        let within = |declared: &[String], allowed: &[String]| {
            allowed.iter().any(|a| a == "*") || declared.iter().all(|d| allowed.contains(d))
        };
        if let Some(csp) = &app.csp {
            let axes = [
                (
                    "connect_domains",
                    &csp.connect_domains,
                    &self.csp_policy.connect_domains,
                ),
                (
                    "resource_domains",
                    &csp.resource_domains,
                    &self.csp_policy.resource_domains,
                ),
                (
                    "frame_domains",
                    &csp.frame_domains,
                    &self.csp_policy.frame_domains,
                ),
            ];
            for (name, declared, allowed) in axes {
                if !within(declared, allowed) {
                    anyhow::bail!(
                        "apps.registry[{}]: strict mode — csp.{name} declares domains outside \
                         the operator csp_policy.{name} allow-list",
                        app.id
                    );
                }
            }
        }
        for perm in &app.permissions {
            if !self.allowed_permissions.contains(perm) {
                anyhow::bail!(
                    "apps.registry[{}]: strict mode — permission {perm:?} is outside \
                     apps.allowed_permissions",
                    app.id
                );
            }
        }
        Ok(())
    }
}

/// True when `id` is a legal `ui://mcpg/<id>` authority segment.
fn is_valid_app_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ---------------------------------------------------------------------------
// Templated MCP Apps registry — config model only. The gateway ships
// one reviewed HTML bundle per kind; the operator supplies only the
// declarative binding below; compilation lives in the runtime layer.
// ---------------------------------------------------------------------------

/// One gateway-authored templated app. Minted as `ui://mcpg/<id>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatewayAppConfig {
    /// Unique id; becomes the `ui://mcpg/<id>` authority path segment.
    /// `[a-z0-9]` then `[a-z0-9-]*`.
    pub id: String,
    /// Which shipped shell renders this app.
    pub kind: GatewayAppKind,
    /// Human title shown in the resource descriptor.
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Data-source tool. Required for `form`; optional for static kinds
    /// (e.g. a `signature_pad`). Its `outputSchema`/`inputSchema` seeds
    /// the columns/fields when those are omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_tool: Option<String>,
    /// Static argument template passed to `data_tool` on the initial
    /// load (named string args; richer typing is a later phase).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_args: Option<std::collections::BTreeMap<String, String>>,
    /// JSON-path to the row array inside the tool's structuredContent.
    /// Default introspected from the output schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows_path: Option<String>,
    /// JSON-path to a row's stable id. Default `$.id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Explicit columns. `None` ⇒ derived from `data_tool.outputSchema`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<AppColumn>>,
    /// Explicit detail/form fields. `None` ⇒ derived from the schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<AppField>>,
    /// Widget/layout overlay (highest precedence over columns/fields).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_schema: Option<UiSchema>,
    /// Per-row actions, each re-entering the gateway via `tools/call`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_actions: Vec<AppRowAction>,
    /// `row_actions[].id` fired on a row click / primary interaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_action: Option<String>,
    /// Read-only App-Provided Tools the app exposes to the agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_tools: Vec<AppProvidedTool>,
    /// Map binding; present iff `kind == map`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map: Option<MapAppConfig>,
    /// Per-app author CSP declaration (still intersected by the egress
    /// `csp_policy` — declaring an axis never widens it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csp: Option<AppCspDecl>,
    /// iframe permissions the app requests (clamped by `allowed_permissions`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<AppsPermission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefers_border: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<AppTheme>,
    /// Opt-in non-secret config values injected into the data island.
    /// `cred://` here requires `allow_credential_values`.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub public_values: std::collections::BTreeMap<String, String>,
    /// Gate that must be set for `cred://` to appear in `public_values`.
    #[serde(default)]
    pub allow_credential_values: bool,
}

/// The shipped shells a templated app can select.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GatewayAppKind {
    Table,
    List,
    Detail,
    Form,
    Confirmation,
    Selection,
    Map,
    /// Dense label/value spec sheet (a compact `detail`).
    KeyValue,
    /// Read-only syntax-highlight-free code/text viewer.
    CodeViewer,
    /// Numeric series chart (bar/line) over the result columns.
    Chart,
    /// Canvas to draw a signature/sketch; submits a PNG data URL.
    SignaturePad,
    /// Record audio (microphone) and submit the clip.
    AudioRecorder,
    /// Capture a still photo (camera) and submit it.
    CameraCapture,
    /// Play an audio/video asset referenced by the result.
    MediaPlayer,
    /// Browse a set of images from the result.
    ImageGallery,
    /// Select/drag files and submit their contents.
    FileUpload,
}

/// A table column bound to a JSON-path over each row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppColumn {
    /// JSON-path into the row object.
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default)]
    pub format: ColumnFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub align: Option<Align>,
    /// Client-evaluated visibility expression over the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_if: Option<String>,
}

/// A detail/form field bound to a JSON-path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppField {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ColumnFormat>,
}

/// How a cell value is rendered client-side.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ColumnFormat {
    #[default]
    Text,
    Number,
    Currency,
    Date,
    Badge,
    Link,
}

/// Horizontal cell alignment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Align {
    Start,
    Center,
    End,
}

/// A per-row action: a `tools/call` with arguments mapped from the row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppRowAction {
    pub id: String,
    pub label: String,
    /// The tool this action invokes (re-enters the full pipeline).
    pub tool: String,
    /// argName → JSON-path over the row.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub arg_map: std::collections::BTreeMap<String, String>,
    /// Optional confirmation prompt before firing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// Widget/layout overlay — the tight mcpg-native uiSchema subset.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UiSchema {
    /// Explicit field render order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    /// Labelled field groups / sections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<UiGroup>>,
    /// field-path → widget specification.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub widgets: std::collections::BTreeMap<String, UiWidget>,
}

/// A labelled group of fields in a form/detail layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UiGroup {
    pub label: String,
    pub fields: Vec<String>,
}

/// How a single field renders, plus its client-evaluated rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UiWidget {
    pub widget: WidgetKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Client-evaluated visibility expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_if: Option<String>,
    /// Client-evaluated conditional-required expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_if: Option<String>,
    /// Options sourced from a sibling tool result (via the action proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_from: Option<EnumSource>,
}

/// The closed widget vocabulary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WidgetKind {
    Text,
    Textarea,
    Select,
    Multiselect,
    Date,
    Datetime,
    Number,
    Currency,
    Slider,
    Toggle,
    Radio,
    File,
    Color,
    Hidden,
    Markdown,
    Json,
    /// Repeatable list of scalar inputs → a JSON array value.
    Array,
}

/// A dynamic-enum source: a sibling tool whose result supplies options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnumSource {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<std::collections::BTreeMap<String, String>>,
    pub label_field: String,
    pub value_field: String,
}

/// Map binding for `kind == map`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MapAppConfig {
    /// Render mode. `plot` (default) needs no network; `raster_tiles`
    /// fetches from `tile_url` and requires a CSP allowance.
    #[serde(default)]
    pub mode: MapRenderMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lat_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lng_field: Option<String>,
    /// JSON-path to a GeoJSON FeatureCollection (alternative to lat/lng).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geojson_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub popup_field: Option<String>,
    /// Raster tile template URL (raster mode only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tile_url: Option<String>,
    /// Tool a region-draw selection invokes (geometry passed as args).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select_action: Option<String>,
}

/// Map rendering mode.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MapRenderMode {
    /// Coordinate plot on a canvas — zero network, no CSP delta.
    #[default]
    Plot,
    /// Raster basemap tiles — needs `tile_url` + a CSP allowance.
    RasterTiles,
}

/// Per-app author CSP declaration. Each axis is still intersected by the
/// egress `csp_policy`; declaring an axis can only narrow, never widen.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppCspDecl {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connect_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frame_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_domains: Vec<String>,
}

/// A read-only App-Provided Tool: surfaces client state to the agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppProvidedTool {
    /// Advertised name; the host sees it auto-prefixed `app.<id>.<name>`.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Which whitelisted client reader backs this tool.
    pub source: AppToolSource,
}

/// The whitelisted read-only client state sources for App-Provided Tools.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppToolSource {
    Selection,
    VisibleRows,
    FormDraft,
    MapViewport,
}

/// Accent + density theming hints for the shell.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppTheme {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub density: Option<AppDensity>,
}

/// Layout density.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AppDensity {
    Comfortable,
    Compact,
}

impl GatewayAppConfig {
    /// Structural validation of one app (the registry already checked the
    /// id grammar + uniqueness). Tool existence is cross-checked later,
    /// post-catalog-build.
    fn validate(&self) -> Result<()> {
        match self.kind {
            GatewayAppKind::Form if self.data_tool.is_none() => {
                anyhow::bail!("kind 'form' requires a data_tool — its inputSchema drives the form");
            }
            GatewayAppKind::Map => {
                let map = self
                    .map
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("kind 'map' requires a `map:` block"))?;
                let has_coords = map.lat_field.is_some() && map.lng_field.is_some();
                if !has_coords && map.geojson_path.is_none() {
                    anyhow::bail!("map: needs either lat_field+lng_field or geojson_path");
                }
                if map.mode == MapRenderMode::RasterTiles && map.tile_url.is_none() {
                    anyhow::bail!(
                        "map.mode 'raster_tiles' requires tile_url (and the host must be \
                         allowed in `csp`)"
                    );
                }
            }
            _ => {}
        }
        if self.map.is_some() && self.kind != GatewayAppKind::Map {
            anyhow::bail!("a `map:` block is only valid on kind 'map'");
        }
        // `csp.redirect_domains` has no on-wire representation for a
        // gateway-authored app (the shell renders sanitized links, never
        // `openExternal`); accepting it would give false confidence.
        if let Some(csp) = &self.csp
            && !csp.redirect_domains.is_empty()
        {
            anyhow::bail!(
                "csp.redirect_domains has no effect on gateway-authored apps — remove it"
            );
        }
        if let Some(pa) = &self.primary_action
            && !self.row_actions.iter().any(|a| &a.id == pa)
        {
            anyhow::bail!("primary_action {pa:?} does not match any row_actions[].id");
        }
        let mut tool_names = std::collections::BTreeSet::new();
        for t in &self.app_tools {
            if !tool_names.insert(t.name.as_str()) {
                anyhow::bail!("duplicate app_tools name {:?}", t.name);
            }
        }
        // Credential firewall: a secret-provider reference (`cred://`,
        // `vault://`, `env://`, …) may appear ONLY in public_values, and
        // only when allow_credential_values is set. Everywhere else
        // (binding fields, arg_maps, data_args, ui_schema exprs) it is an
        // error — those positions are evaluated against request data and
        // serialized into the client-visible data island, so they must
        // never carry a secret reference. NOTE: this guards *references*,
        // not literal secret VALUES — every binding field is operator-
        // authored, client-visible plaintext, so a pasted literal secret
        // is operator self-harm (equivalent to a secret in a static HTML
        // template); do not paste secrets into binding fields.
        let mut probe = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = probe.as_object_mut() {
            obj.remove("public_values");
        }
        if json_contains_secret_ref(&probe) {
            anyhow::bail!(
                "a secret reference (cred://, vault://, env://, …) is not allowed in \
                 binding/app fields — secrets belong in public_values \
                 (with allow_credential_values: true)"
            );
        }
        if !self.allow_credential_values {
            for (k, v) in &self.public_values {
                if contains_secret_ref(v) {
                    anyhow::bail!(
                        "public_values.{k}: a secret reference requires \
                         allow_credential_values: true"
                    );
                }
            }
        }
        Ok(())
    }
}

/// Secret-provider URI schemes the gateway resolves. A reference using
/// any of these in a client-visible app binding is a config error.
const SECRET_REF_SCHEMES: [&str; 9] = [
    "cred",
    "secret",
    "env",
    "file",
    "vault",
    "aws-sm",
    "aws-secrets",
    "gcp-sm",
    "azure-kv",
];

/// True when `s` contains a `<secret-scheme>://` reference (case-insensitive).
/// Transport/data URLs (`http(s)://`, `mailto:` …) are deliberately allowed —
/// apps legitimately carry them (tile URLs, links).
pub(crate) fn contains_secret_ref(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    SECRET_REF_SCHEMES
        .iter()
        .any(|scheme| lower.contains(&format!("{scheme}://")))
}

/// Recursively scan a JSON value's strings for a secret-provider reference.
fn json_contains_secret_ref(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => contains_secret_ref(s),
        serde_json::Value::Array(a) => a.iter().any(json_contains_secret_ref),
        serde_json::Value::Object(o) => o.values().any(json_contains_secret_ref),
        _ => false,
    }
}

#[cfg(test)]
mod apps_config_tests {
    use super::*;

    #[test]
    fn apps_default_is_disabled_with_sane_policy_defaults() {
        let cfg = AppsConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.strict);
        // federate_upstream inherits enabled (false).
        assert!(!cfg.federate_upstream_enabled());
        // CSP defaults: no bound on fetch/connect, frame/base pinned to self.
        assert_eq!(cfg.csp_policy.connect_domains, vec!["*".to_owned()]);
        assert_eq!(cfg.csp_policy.frame_domains, vec!["self".to_owned()]);
        // all four permissions allowed by default.
        assert_eq!(cfg.allowed_permissions.len(), 4);
        assert!(cfg.allowed_domains.is_none());
    }

    #[test]
    fn federate_upstream_can_be_set_independently() {
        let cfg: AppsConfig =
            serde_yaml::from_str("enabled: false\nfederate_upstream: true\n").unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.federate_upstream_enabled());
    }

    #[test]
    fn permission_wire_keys_are_camel_case() {
        assert_eq!(AppsPermission::ClipboardWrite.wire_key(), "clipboardWrite");
        assert_eq!(AppsPermission::Camera.wire_key(), "camera");
    }

    #[test]
    fn compiled_policy_maps_permissions_to_wire_keys() {
        let cfg: AppsConfig =
            serde_yaml::from_str("enabled: true\nallowed_permissions: [camera, clipboard_write]\n")
                .unwrap();
        let policy = cfg.compiled_policy();
        assert_eq!(
            policy.allowed_permissions,
            vec!["camera".to_owned(), "clipboardWrite".to_owned()]
        );
    }

    #[test]
    fn empty_allowed_domains_is_rejected() {
        let cfg: AppsConfig = serde_yaml::from_str("enabled: true\nallowed_domains: []\n").unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn full_config_round_trips() {
        let cfg: AppsConfig = serde_yaml::from_str(
            r#"
enabled: true
federate_upstream: true
strict: true
csp_policy:
  connect_domains: ["api.example.com"]
  resource_domains: ["*"]
  frame_domains: ["self"]
  base_uri_domains: ["self"]
allowed_permissions: [camera, geolocation]
allowed_domains: ["trusted.example.com"]
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());
        assert!(cfg.strict);
        assert_eq!(
            cfg.csp_policy.connect_domains,
            vec!["api.example.com".to_owned()]
        );
        let policy = cfg.compiled_policy();
        assert!(policy.strict);
        assert_eq!(
            policy.allowed_domains,
            Some(vec!["trusted.example.com".to_owned()])
        );
    }

    // ── templated-app registry ──

    fn apps(yaml: &str) -> AppsConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn registry_round_trips_and_validates() {
        let cfg = apps(
            r#"
enabled: true
registry:
  - id: customers-table
    kind: table
    title: Customers
    data_tool: crm.list_customers
    columns:
      - { field: $.name, header: Name }
      - { field: $.balance, header: Balance, format: currency, align: end }
    row_actions:
      - { id: open, label: Open, tool: crm.get_customer, arg_map: { id: $.id } }
    primary_action: open
  - id: new-invoice
    kind: form
    title: New invoice
    data_tool: qbo.create_invoice
"#,
        );
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.registry.len(), 2);
        assert_eq!(cfg.registry[0].kind, GatewayAppKind::Table);
        // round-trip
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: AppsConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn registry_requires_enabled() {
        let cfg = apps(
            "enabled: false\nregistry:\n  - { id: a, kind: list, title: A, data_tool: t.list }\n",
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn registry_rejects_duplicate_ids() {
        let cfg = apps(
            "enabled: true\nregistry:\n  - { id: dup, kind: list, title: A }\n  - { id: dup, kind: list, title: B }\n",
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn registry_rejects_bad_id() {
        for bad in ["-leading", "Caps", "has space", "under_score", ""] {
            let cfg = apps(&format!(
                "enabled: true\nregistry:\n  - {{ id: \"{bad}\", kind: list, title: A }}\n"
            ));
            assert!(cfg.validate().is_err(), "id {bad:?} should be rejected");
        }
    }

    #[test]
    fn form_requires_data_tool() {
        let cfg = apps("enabled: true\nregistry:\n  - { id: f, kind: form, title: F }\n");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn map_kind_requires_map_block_and_coords() {
        let no_block = apps("enabled: true\nregistry:\n  - { id: m, kind: map, title: M }\n");
        assert!(no_block.validate().is_err());

        let raster_needs_tile = apps(
            r#"
enabled: true
registry:
  - id: m
    kind: map
    title: M
    map: { mode: raster_tiles, lat_field: $.lat, lng_field: $.lng }
"#,
        );
        assert!(raster_needs_tile.validate().is_err());

        let ok = apps(
            r#"
enabled: true
registry:
  - id: m
    kind: map
    title: M
    data_tool: geo.list
    map: { lat_field: $.lat, lng_field: $.lng }
"#,
        );
        assert!(ok.validate().is_ok());
        assert_eq!(
            ok.registry[0].map.as_ref().unwrap().mode,
            MapRenderMode::Plot
        );
    }

    #[test]
    fn map_block_only_on_map_kind() {
        let cfg = apps(
            "enabled: true\nregistry:\n  - { id: t, kind: table, title: T, map: { lat_field: $.a, lng_field: $.b } }\n",
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn cred_in_binding_is_rejected() {
        let cfg = apps(
            r#"
enabled: true
registry:
  - id: leak
    kind: table
    title: Leak
    data_tool: t.list
    columns:
      - { field: "cred://vault/secret" }
"#,
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn cred_in_public_values_is_gated() {
        let denied = apps(
            r#"
enabled: true
registry:
  - id: pv
    kind: detail
    title: PV
    data_tool: t.get
    public_values: { token: "cred://vault/x" }
"#,
        );
        assert!(denied.validate().is_err());

        let allowed = apps(
            r#"
enabled: true
registry:
  - id: pv
    kind: detail
    title: PV
    data_tool: t.get
    allow_credential_values: true
    public_values: { token: "cred://vault/x" }
"#,
        );
        assert!(allowed.validate().is_ok());
    }

    #[test]
    fn primary_action_must_match_a_row_action() {
        let cfg = apps(
            "enabled: true\nregistry:\n  - { id: t, kind: table, title: T, data_tool: t.list, primary_action: nope }\n",
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn firewall_rejects_non_cred_secret_schemes_and_case_variants() {
        for r in [
            "vault://secret/x",
            "env://SECRET",
            "aws-sm://k",
            "CRED://vault/y",
            "File://x",
        ] {
            let cfg = apps(&format!(
                "enabled: true\nregistry:\n  - {{ id: t, kind: table, title: T, data_tool: t.list, columns: [{{ field: \"{r}\" }}] }}\n"
            ));
            assert!(
                cfg.validate().is_err(),
                "secret ref {r:?} should be rejected in a binding"
            );
        }
        // transport/data URLs are allowed (apps legitimately carry them)
        let ok = apps(
            "enabled: true\nregistry:\n  - { id: m, kind: map, title: M, data_tool: geo.list, map: { mode: raster_tiles, lat_field: $.lat, lng_field: $.lng, tile_url: \"https://tiles.example/{z}/{x}/{y}.png\" } }\n",
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn firewall_public_values_gate_is_case_insensitive_and_broad() {
        let denied = apps(
            "enabled: true\nregistry:\n  - { id: p, kind: detail, title: P, data_tool: t.get, public_values: { k: \"VAULT://s\" } }\n",
        );
        assert!(denied.validate().is_err());
        let allowed = apps(
            "enabled: true\nregistry:\n  - { id: p, kind: detail, title: P, data_tool: t.get, allow_credential_values: true, public_values: { k: \"vault://s\" } }\n",
        );
        assert!(allowed.validate().is_ok());
    }

    #[test]
    fn rejects_inert_redirect_domains_on_authored_app() {
        let cfg = apps(
            "enabled: true\nregistry:\n  - { id: t, kind: table, title: T, data_tool: t.list, csp: { redirect_domains: [\"x.example\"] } }\n",
        );
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn strict_mode_rejects_app_csp_wider_than_policy() {
        let cfg = apps(
            r#"
enabled: true
strict: true
csp_policy:
  connect_domains: ["api.example.com"]
registry:
  - id: t
    kind: table
    title: T
    data_tool: t.list
    csp: { connect_domains: ["api.example.com", "evil.com"] }
"#,
        );
        assert!(cfg.validate().is_err());
        // within policy ⇒ ok under strict
        let ok = apps(
            r#"
enabled: true
strict: true
csp_policy:
  connect_domains: ["api.example.com"]
registry:
  - id: t
    kind: table
    title: T
    data_tool: t.list
    csp: { connect_domains: ["api.example.com"] }
"#,
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn phase3b_kinds_and_array_widget_parse() {
        let cfg = apps(
            r#"
enabled: true
registry:
  - { id: kv, kind: key_value, title: KV, data_tool: t.get }
  - { id: cv, kind: code_viewer, title: CV, data_tool: t.get }
  - { id: ch, kind: chart, title: CH, data_tool: t.series }
  - id: f
    kind: form
    title: F
    data_tool: t.create
    ui_schema:
      widgets:
        tags: { widget: array }
"#,
        );
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.registry.len(), 4);
        assert_eq!(cfg.registry[0].kind, GatewayAppKind::KeyValue);
    }

    #[test]
    fn phase4b_media_kinds_parse() {
        let cfg = apps(
            r#"
enabled: true
registry:
  - { id: sig, kind: signature_pad, title: Sign, data_tool: save.sig }
  - { id: cam, kind: camera_capture, title: Photo, data_tool: save.photo, permissions: [camera] }
  - { id: rec, kind: audio_recorder, title: Rec, data_tool: save.audio, permissions: [microphone] }
  - { id: play, kind: media_player, title: Play, data_tool: media.get }
  - { id: gal, kind: image_gallery, title: Gallery, data_tool: img.list }
  - { id: up, kind: file_upload, title: Up, data_tool: files.put }
"#,
        );
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.registry.len(), 6);
    }

    #[test]
    fn registry_rejects_unknown_field() {
        let err: std::result::Result<AppsConfig, _> = serde_yaml::from_str(
            "enabled: true\nregistry:\n  - { id: t, kind: table, title: T, bogus: 1 }\n",
        );
        assert!(err.is_err());
    }

    #[test]
    fn empty_registry_is_noop() {
        let cfg = apps("enabled: false\n");
        assert!(cfg.registry.is_empty());
        assert!(cfg.validate().is_ok());
    }

    // ── app-id authority grammar (the `ui://mcpg/<id>` injection guard) ──

    #[test]
    fn app_id_grammar_accepts_canonical_labels() {
        for id in ["a", "0", "x9", "crm-customers", "a-b-c-9", "table0"] {
            assert!(is_valid_app_id(id), "should accept {id:?}");
        }
    }

    // A registry holding exactly one app with `id` — built through serde so the
    // string can carry arbitrary bytes (control chars, separators) that YAML
    // would mangle.
    fn registry_with_id(id: &str) -> std::result::Result<AppsConfig, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "registry": [{
                "id": id,
                "kind": "table",
                "title": "T",
                "data_tool": "t.list",
            }],
        }))
    }

    #[test]
    fn app_id_grammar_rejects_authority_and_path_injection() {
        // The id becomes the path segment of `ui://mcpg/<id>`. Anything that
        // could change the authority, climb the path, smuggle a scheme, or
        // carry a control/whitespace byte must be rejected at config load so
        // a minted resource can never escape the frozen `mcpg` authority.
        let adversarial = [
            "",            // empty
            "-lead",       // leading hyphen
            "Cap",         // uppercase
            "MiXeD",       // mixed case
            "a b",         // space
            " a",          // leading space
            "a\t",         // tab
            "a\n",         // newline
            "a/b",         // path separator
            "..",          // parent traversal
            "../x",        // traversal prefix
            "a/../b",      // embedded traversal
            "a:b",         // scheme/port separator
            "http://evil", // a full URL is not a label
            "ui://mcpg/x", // re-injected authority
            "//host",      // protocol-relative authority
            "a#frag",      // fragment
            "a?q=1",       // query
            "a@host",      // userinfo
            "a%2e%2e",     // percent-encoded dot-dot
            "a%2fb",       // percent-encoded slash
            "a\\b",        // backslash
            "a.b",         // dot (not in grammar)
            "café",        // non-ASCII
            "a\u{0000}b",  // null byte
            "a\u{2028}b",  // line separator
            "a_b",         // underscore (not in grammar)
            "a b/c",       // mixed
        ];
        for id in adversarial {
            assert!(!is_valid_app_id(id), "should reject {id:?}");
            // …and the registry validator must reject it too (serde parses the
            // raw string fine; validate() is the gate that must catch it).
            let cfg = registry_with_id(id).expect("registry parses");
            assert!(cfg.validate().is_err(), "registry must reject id {id:?}");
        }
    }

    #[test]
    fn app_id_grammar_property_matches_regex_over_pseudo_random_inputs() {
        // Deterministic LCG over a byte alphabet that deliberately oversamples
        // URI-significant characters. The grammar invariant: an id is valid
        // iff its first byte is `[a-z0-9]` and every byte is `[a-z0-9-]`.
        const ALPHABET: &[u8] = b"abz09-/.:%@# \t\\_ABZ";
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..20_000 {
            let len = next() % 8;
            let id: String = (0..len)
                .map(|_| ALPHABET[next() % ALPHABET.len()] as char)
                .collect();
            let expected = !id.is_empty()
                && id
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            assert_eq!(
                is_valid_app_id(&id),
                expected,
                "grammar mismatch for {id:?}"
            );
        }
    }
}
