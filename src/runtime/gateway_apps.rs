//! Compilation of gateway-authored templated MCP apps.
//!
//! Each `mcp.configurations.apps.registry[]` entry is compiled once (at
//! boot / hot-reload) into a [`CompiledApp`]: a fully-rendered
//! `text/html;profile=mcp-app` body and the `_meta.ui` for its
//! `ui://mcpg/<id>` resource descriptor. The runtime serves the
//! precompiled body verbatim on `resources/read` and lists the
//! descriptor on `resources/list`.
//!
//! Two contexts, two escapers, never crossed: the HTML shell is a
//! static, reviewed, CSP-clean bundle shipped via `include_str!`; the
//! operator's binding is injected as a JSON **data island**
//! (`<script type="application/json">`) read with `JSON.parse` — never
//! `window.X = {…}`, and never emitted as JavaScript. The island text is
//! escaped so a hostile string value cannot break out of the script tag.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::config::apps::{AppColumn, AppField, ColumnFormat, GatewayAppConfig, GatewayAppKind};
use crate::protocol::shared::apps::{AppsPolicy, UI_MIME_TYPE};

/// A bound tool's JSON schemas, used to derive columns/fields when the
/// operator omits them (schema-introspection defaults).
#[derive(Debug, Clone, Default)]
pub struct ToolIo {
    pub input_schema: Option<Value>,
    pub output_schema: Option<Value>,
}

/// The static, reviewed app shell. The single `<!--MCPG_APP_CONFIG-->`
/// marker is replaced with the JSON data island at compile time.
const APP_SHELL: &str = include_str!("assets/gateway_apps_shell.html");

const CONFIG_MARKER: &str = "<!--MCPG_APP_CONFIG-->";

/// Upper bound on auto-derived columns/fields per app — bounds the
/// compiled-HTML size from a large (possibly federated) tool schema.
const MAX_DERIVED_FIELDS: usize = 100;

/// A compiled gateway app, ready to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledApp {
    pub id: String,
    /// `ui://mcpg/<id>`.
    pub uri: String,
    pub title: String,
    pub description: Option<String>,
    /// Authored `_meta.ui` for the resource descriptor + read content,
    /// already clamped by the operator [`AppsPolicy`].
    pub descriptor_meta: Value,
    /// The fully-rendered `text/html;profile=mcp-app` body.
    pub html: String,
    /// Stable content hash of the rendered body, served as the
    /// `cache_token` so a host can privately cache the (static) app and
    /// revalidate cheaply; changes whenever the compiled body changes.
    pub cache_token: String,
}

impl CompiledApp {
    /// Build the `resources/list` descriptor for this app.
    pub fn to_descriptor(&self) -> crate::backends::ResourceDescriptor {
        crate::backends::ResourceDescriptor {
            uri: self.uri.clone(),
            name: self.id.clone(),
            title: Some(self.title.clone()),
            description: self.description.clone(),
            mime_type: Some(UI_MIME_TYPE.to_owned()),
            size: None,
            icons: None,
            annotations: None,
            meta: Some(self.descriptor_meta.clone()),
        }
    }
}

/// Compile every app in the registry. `policy` (when apps are enabled)
/// clamps each authored `_meta.ui` so the descriptor can never advertise
/// wider than operator policy. `tools` supplies the bound tools' schemas
/// for the introspection defaults.
///
/// `tools` is a boot/reload-time snapshot of the tool catalog. An app whose
/// `data_tool` is imported *after* boot (e.g. a federated tool) will have no
/// introspected columns/fields until the next config reload — such apps
/// should declare explicit `columns`/`fields`.
pub fn compile_apps(
    registry: &[GatewayAppConfig],
    policy: Option<&AppsPolicy>,
    tools: &BTreeMap<String, ToolIo>,
) -> Vec<CompiledApp> {
    registry
        .iter()
        .map(|cfg| compile_app(cfg, policy, tools))
        .collect()
}

fn compile_app(
    cfg: &GatewayAppConfig,
    policy: Option<&AppsPolicy>,
    tools: &BTreeMap<String, ToolIo>,
) -> CompiledApp {
    let uri = format!("ui://mcpg/{}", cfg.id);
    let window_config = build_window_config(cfg, tools);
    let html = render_html(&window_config);
    let descriptor_meta = build_descriptor_meta(cfg, &uri, policy);
    let cache_token = blake3::hash(html.as_bytes()).to_hex().as_str()[..16].to_owned();
    CompiledApp {
        id: cfg.id.clone(),
        uri,
        title: cfg.title.clone(),
        description: cfg.description.clone(),
        descriptor_meta,
        html,
        cache_token,
    }
}

/// The binding object injected into the data island. It is the app
/// config minus the credential surface (`public_values` /
/// `allow_credential_values` never reach the client in v1 — credential
/// resolution is not wired yet), plus a `schema_version`.
fn build_window_config(cfg: &GatewayAppConfig, tools: &BTreeMap<String, ToolIo>) -> Value {
    let mut v = serde_json::to_value(cfg).unwrap_or_else(|_| json!({}));
    let io = cfg.data_tool.as_deref().and_then(|t| tools.get(t));
    if let Some(obj) = v.as_object_mut() {
        obj.remove("allow_credential_values");
        // Inject only NON-secret public_values into the client island
        // (plain config the app may read — labels, public tokens, flags).
        // Entries carrying a secret reference are dropped: app-side
        // credential resolution is not yet wired.
        let drop_pv = if let Some(pv) = obj.get_mut("public_values").and_then(Value::as_object_mut)
        {
            pv.retain(|_, val| {
                val.as_str()
                    .map(|s| !crate::config::apps::contains_secret_ref(s))
                    .unwrap_or(true)
            });
            pv.is_empty()
        } else {
            false
        };
        if drop_pv {
            obj.remove("public_values");
        }
        obj.insert("schema_version".to_owned(), json!(1));

        // Schema-introspection defaults: when the operator
        // omits columns (table/list/selection) or fields (detail/form),
        // derive them from the bound tool's output/input schema. Explicit
        // config always wins; introspection only fills the gap.
        if let Some(io) = io {
            match cfg.kind {
                GatewayAppKind::Table
                | GatewayAppKind::List
                | GatewayAppKind::Selection
                | GatewayAppKind::Chart => {
                    if cfg.columns.is_none()
                        && let Some(out) = &io.output_schema
                    {
                        let cols = derive_columns(out, cfg.rows_path.as_deref());
                        if !cols.is_empty() {
                            obj.insert(
                                "columns".to_owned(),
                                serde_json::to_value(&cols).unwrap_or_else(|_| json!([])),
                            );
                        }
                    }
                }
                GatewayAppKind::Detail | GatewayAppKind::KeyValue => {
                    if cfg.fields.is_none()
                        && let Some(out) = &io.output_schema
                    {
                        let fields = derive_fields(out, true);
                        if !fields.is_empty() {
                            obj.insert(
                                "fields".to_owned(),
                                serde_json::to_value(&fields).unwrap_or_else(|_| json!([])),
                            );
                        }
                    }
                }
                GatewayAppKind::Form => {
                    if cfg.fields.is_none()
                        && let Some(inp) = &io.input_schema
                    {
                        let fields = derive_fields(inp, false);
                        if !fields.is_empty() {
                            obj.insert(
                                "fields".to_owned(),
                                serde_json::to_value(&fields).unwrap_or_else(|_| json!([])),
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // App-Provided Tool names are host-facing; auto-prefix `app.<id>.`
        // so they can never shadow a real catalog tool.
        if let Some(tools) = obj.get_mut("app_tools").and_then(Value::as_array_mut) {
            for t in tools.iter_mut() {
                if let Some(t_obj) = t.as_object_mut() {
                    let name = t_obj.get("name").and_then(Value::as_str).map(str::to_owned);
                    if let Some(name) = name {
                        t_obj.insert("name".to_owned(), json!(format!("app.{}.{name}", cfg.id)));
                    }
                }
            }
        }
    }
    v
}

/// Derive table columns from a tool's `outputSchema`. Resolves the
/// per-row object schema (an array's `items`, or the array property the
/// rows live under) and maps each property to a column.
fn derive_columns(output_schema: &Value, rows_path: Option<&str>) -> Vec<AppColumn> {
    let Some(item) = row_item_schema(output_schema, rows_path) else {
        return Vec::new();
    };
    object_properties(item)
        .into_iter()
        .filter(|(key, _)| is_simple_key(key))
        .take(MAX_DERIVED_FIELDS)
        .map(|(key, schema)| AppColumn {
            field: format!("$.{key}"),
            header: Some(titlecase(&key)),
            format: infer_format(&schema),
            width: None,
            align: None,
            visible_if: None,
        })
        .collect()
}

/// Derive detail/form fields from an object schema. `as_path` ⇒ the
/// field is a JSON-path into the result (`$.<k>`, for `detail`); else the
/// bare input argument name (for `form`).
fn derive_fields(schema: &Value, as_path: bool) -> Vec<AppField> {
    object_properties(schema)
        .into_iter()
        .filter(|(key, _)| is_simple_key(key))
        .take(MAX_DERIVED_FIELDS)
        .map(|(key, prop)| AppField {
            field: if as_path {
                format!("$.{key}")
            } else {
                key.clone()
            },
            label: Some(
                prop.get("title")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| titlecase(&key)),
            ),
            format: Some(infer_format(&prop)),
        })
        .collect()
}

/// Resolve the per-row object schema inside an `outputSchema`: the
/// `items` of a top-level array, or of the (rows_path-named, else first)
/// array-typed property of an object.
fn row_item_schema<'a>(schema: &'a Value, rows_path: Option<&str>) -> Option<&'a Value> {
    if schema_type_is(schema, "array") {
        return schema.get("items");
    }
    let props = schema.get("properties").and_then(Value::as_object)?;
    // Prefer the property the rows live under, if named by rows_path.
    if let Some(path) = rows_path {
        let key = path
            .trim_start_matches("$.")
            .split('.')
            .next_back()
            .unwrap_or(path);
        if let Some(p) = props.get(key)
            && schema_type_is(p, "array")
        {
            return p.get("items");
        }
    }
    // Otherwise the first array-typed property.
    props
        .values()
        .find(|p| schema_type_is(p, "array"))
        .and_then(|p| p.get("items"))
}

/// The `properties` of an object schema, in declaration order.
fn object_properties(schema: &Value) -> Vec<(String, Value)> {
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Map a JSON-schema property to a cell render format.
fn infer_format(prop: &Value) -> ColumnFormat {
    if schema_type_is(prop, "number") || schema_type_is(prop, "integer") {
        return ColumnFormat::Number;
    }
    if schema_type_is(prop, "string") {
        match prop.get("format").and_then(Value::as_str) {
            Some("date" | "date-time") => return ColumnFormat::Date,
            Some("uri" | "uri-reference" | "url") => return ColumnFormat::Link,
            _ => {}
        }
    }
    ColumnFormat::Text
}

/// True when a schema node's `type` is (or includes) `wanted`. Tolerates
/// the JSON-schema `type: [..]` union form.
fn schema_type_is(schema: &Value, wanted: &str) -> bool {
    match schema.get("type") {
        Some(Value::String(s)) => s == wanted,
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some(wanted)),
        _ => false,
    }
}

/// `first_name` / `first-name` / `firstName` → `First Name`.
fn titlecase(key: &str) -> String {
    let spaced = key.replace(['_', '-', '.'], " ");
    let mut out = String::with_capacity(spaced.len() + 4);
    let mut prev_lower = false;
    for (i, ch) in spaced.chars().enumerate() {
        // split camelCase boundaries
        if ch.is_ascii_uppercase() && prev_lower {
            out.push(' ');
        }
        prev_lower = ch.is_ascii_lowercase();
        if i == 0 || out.ends_with(' ') {
            out.extend(ch.to_uppercase());
        } else {
            out.push(ch);
        }
    }
    // collapse whitespace (leading-separator / repeated-separator keys) and
    // fall back to the raw key if the result is empty.
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        key.to_owned()
    } else {
        collapsed
    }
}

/// A property key safe to address with the shell's dotted JSON-path: a `.`
/// would be mis-split into false nesting, so such keys are skipped by
/// introspection (the operator can bind them with explicit columns/fields).
fn is_simple_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('.')
}

/// Author the resource `_meta.ui`, then clamp it with the operator
/// policy (belt-and-suspenders: the read/list egress path clamps again,
/// idempotently).
fn build_descriptor_meta(cfg: &GatewayAppConfig, uri: &str, policy: Option<&AppsPolicy>) -> Value {
    let mut ui = serde_json::Map::new();
    ui.insert("resourceUri".to_owned(), json!(uri));

    if let Some(csp) = &cfg.csp {
        let mut axes = serde_json::Map::new();
        if !csp.connect_domains.is_empty() {
            axes.insert("connectDomains".to_owned(), json!(csp.connect_domains));
        }
        if !csp.resource_domains.is_empty() {
            axes.insert("resourceDomains".to_owned(), json!(csp.resource_domains));
        }
        if !csp.frame_domains.is_empty() {
            axes.insert("frameDomains".to_owned(), json!(csp.frame_domains));
        }
        if !axes.is_empty() {
            ui.insert("csp".to_owned(), Value::Object(axes));
        }
    }

    if !cfg.permissions.is_empty() {
        let mut perms = serde_json::Map::new();
        for perm in &cfg.permissions {
            perms.insert(perm.wire_key().to_owned(), json!({}));
        }
        ui.insert("permissions".to_owned(), Value::Object(perms));
    }

    if let Some(border) = cfg.prefers_border {
        ui.insert("prefersBorder".to_owned(), json!(border));
    }

    let mut meta = json!({ "ui": Value::Object(ui) });
    if let Some(policy) = policy {
        let _ = policy.apply_to_resource_meta(&mut meta);
    }
    meta
}

/// Inject the data island into the static shell.
fn render_html(window_config: &Value) -> String {
    APP_SHELL.replacen(CONFIG_MARKER, &data_island(window_config), 1)
}

/// Serialize the binding as a `<script type="application/json">` data
/// island, escaped so no string value can terminate the script tag or
/// inject markup.
fn data_island(config: &Value) -> String {
    let json = serde_json::to_string(config).unwrap_or_else(|_| "{}".to_owned());
    format!(
        "<script type=\"application/json\" id=\"mcpg-app-config\">{}</script>",
        escape_for_script(&json)
    )
}

/// Escape a JSON document for safe embedding inside an HTML
/// `<script>` element. `<`, `>`, `&` and the U+2028/U+2029 line
/// separators become `\uXXXX` escapes — valid inside a JSON string,
/// decoded back by `JSON.parse`, but unable to form `</script>` or HTML.
fn escape_for_script(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(yaml: &str) -> GatewayAppConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    fn no_tools() -> BTreeMap<String, ToolIo> {
        BTreeMap::new()
    }

    fn tools_with(name: &str, io: ToolIo) -> BTreeMap<String, ToolIo> {
        let mut m = BTreeMap::new();
        m.insert(name.to_owned(), io);
        m
    }

    /// Dev-only visual-verify dumper. A no-op unless `MCPG_DUMP_APPS_HTML` is
    /// set to an output directory; never runs in CI. For every app kind it
    /// writes the REAL compiled `<id>.html` (via `compile_app`, so the data
    /// island, escaping and `_meta` are production-identical) plus a
    /// `<id>.result.json` sample tool-result and an `index.json` manifest.
    /// The headless-chromium harness (`tools/mcp-apps-visual/shoot.mjs`) loads
    /// each page and `postMessage`s the sample result, then screenshots it.
    /// `__BASE__` in a result URL is rewritten by the harness to its local
    /// HTTP origin so media/gallery images resolve offline.
    #[test]
    fn dump_apps_html_for_visual_verify() {
        let Ok(out) = std::env::var("MCPG_DUMP_APPS_HTML") else {
            return;
        };
        let dir = std::path::Path::new(&out);
        std::fs::create_dir_all(dir).unwrap();

        let specs: &[(&str, Value)] = &[
            (
                r#"
id: customers
kind: table
title: Customers
description: Accounts and balances.
data_tool: crm.list
columns:
  - { field: $.name, header: Name }
  - { field: $.tier, header: Tier, format: badge }
  - { field: $.balance, header: Balance, format: currency, align: end }
  - { field: $.site, header: Site, format: link }
row_actions:
  - { id: open, label: Open, tool: crm.get, arg_map: { id: $.id } }
primary_action: open
"#,
                json!({"structuredContent":{"items":[
                    {"id":"1","name":"Acme Corp","tier":"Gold","balance":12450.5,"site":"https://acme.example"},
                    {"id":"2","name":"Globex","tier":"Silver","balance":830.0,"site":"https://globex.example"},
                    {"id":"3","name":"Initech","tier":"Bronze","balance":-15.25,"site":"https://initech.example"}
                ]}}),
            ),
            (
                r#"
id: orders
kind: list
title: Recent orders
data_tool: shop.orders
columns:
  - { field: $.title, header: Order }
  - { field: $.status, header: Status }
  - { field: $.total, header: Total, format: currency }
row_actions:
  - { id: view, label: View, tool: shop.get, arg_map: { id: $.id } }
primary_action: view
"#,
                json!({"structuredContent":{"items":[
                    {"id":"a","title":"Order #1042","status":"Shipped","total":59.99},
                    {"id":"b","title":"Order #1043","status":"Processing","total":129.0},
                    {"id":"c","title":"Order #1044","status":"Delivered","total":12.5}
                ]}}),
            ),
            (
                r#"
id: account
kind: detail
title: Account detail
data_tool: crm.get
fields:
  - { field: $.name, label: Name }
  - { field: $.email, label: Email }
  - { field: $.balance, label: Balance, format: currency }
  - { field: $.active, label: Active }
row_actions:
  - { id: suspend, label: Suspend, tool: crm.suspend, arg_map: { id: $.id }, confirm: "Suspend this account?" }
"#,
                json!({"structuredContent":{"id":"1","name":"Acme Corp","email":"ap@acme.example","balance":12450.5,"active":true}}),
            ),
            (
                r#"
id: kv
kind: key_value
title: Build metadata
data_tool: ci.meta
fields:
  - { field: $.commit, label: Commit }
  - { field: $.branch, label: Branch }
  - { field: $.builtAt, label: Built, format: date }
"#,
                json!({"structuredContent":{"commit":"5bbaa72c","branch":"develop","builtAt":"2026-06-21T18:44:00Z"}}),
            ),
            (
                r#"
id: revenue
kind: chart
title: Revenue by region
data_tool: fin.byRegion
columns:
  - { field: $.region, header: Region }
  - { field: $.amount, header: Amount, format: currency }
"#,
                json!({"structuredContent":{"items":[
                    {"region":"NA","amount":42000},
                    {"region":"EMEA","amount":31500},
                    {"region":"APAC","amount":18750},
                    {"region":"LATAM","amount":9200}
                ]}}),
            ),
            (
                r#"
id: stores
kind: map
title: Store locations
data_tool: geo.stores
map: { lat_field: $.lat, lng_field: $.lng, label_field: $.name }
row_actions:
  - { id: open, label: Open, tool: geo.get, arg_map: { id: $.id } }
primary_action: open
"#,
                json!({"structuredContent":{"items":[
                    {"id":"1","name":"SF","lat":37.7749,"lng":-122.4194},
                    {"id":"2","name":"NYC","lat":40.7128,"lng":-74.006},
                    {"id":"3","name":"London","lat":51.5072,"lng":-0.1276},
                    {"id":"4","name":"Tokyo","lat":35.6762,"lng":139.6503}
                ]}}),
            ),
            (
                r#"
id: config-src
kind: code_viewer
title: Effective config
data_tool: admin.config
"#,
                json!({"structuredContent":{"text":"server:\n  port: 8080\nmcp:\n  configurations:\n    apps:\n      enabled: true\n"}}),
            ),
            (
                r#"
id: bulk
kind: selection
title: Select records to export
data_tool: crm.list
id_field: $.id
columns:
  - { field: $.name, header: Name }
row_actions:
  - { id: export, label: Export selected, tool: crm.export }
primary_action: export
"#,
                json!({"structuredContent":{"items":[
                    {"id":"1","name":"Acme Corp"},
                    {"id":"2","name":"Globex"},
                    {"id":"3","name":"Initech"}
                ]}}),
            ),
            (
                r#"
id: gallery
kind: image_gallery
title: Product photos
data_tool: img.list
columns:
  - { field: $.url, header: Image, format: link }
row_actions:
  - { id: pick, label: Pick, tool: img.pick, arg_map: { id: $.id } }
primary_action: pick
"#,
                json!({"structuredContent":{"items":[
                    {"id":"1","url":"__BASE__/sample.png"},
                    {"id":"2","url":"__BASE__/sample.png"},
                    {"id":"3","url":"__BASE__/sample.png"}
                ]}}),
            ),
            (
                r#"
id: clip
kind: media_player
title: Media clip
data_tool: media.get
fields:
  - { field: $.url, label: URL }
"#,
                json!({"structuredContent":{"url":"__BASE__/sample.mp4"}}),
            ),
            (
                r#"
id: signup
kind: form
title: Create account
description: Provision a new tenant account.
data_tool: crm.create
fields:
  - { field: name, label: Name }
  - { field: email, label: Email }
  - { field: tier, label: Tier }
  - { field: budget, label: Monthly budget, format: currency }
  - { field: notify, label: Email me updates }
  - { field: notes, label: Notes }
ui_schema:
  order: [name, email, tier, budget, notify, notes]
  groups:
    - { label: Identity, fields: [name, email] }
    - { label: Plan, fields: [tier, budget, notify] }
    - { label: Other, fields: [notes] }
  widgets:
    tier: { widget: select, enum_from: { tool: crm.tiers, value_field: $.id, label_field: $.label } }
    notify: { widget: toggle }
    notes: { widget: textarea, help: "Optional internal notes." }
    budget: { widget: currency, required_if: "${tier == 'Gold'}" }
"#,
                Value::Null,
            ),
            (
                r#"
id: confirm-delete
kind: confirmation
title: Delete workspace?
description: This permanently removes the workspace and all its data.
data_tool: ws.delete
row_actions:
  - { id: delete, label: Delete workspace, tool: ws.delete, arg_map: { id: $.id } }
primary_action: delete
"#,
                Value::Null,
            ),
            (
                r#"
id: sign
kind: signature_pad
title: Sign here
description: Draw your signature to approve.
data_tool: doc.sign
"#,
                Value::Null,
            ),
            (
                r#"
id: upload
kind: file_upload
title: Upload documents
description: Attach one or more files.
data_tool: files.put
"#,
                Value::Null,
            ),
            (
                r#"
id: photo
kind: camera_capture
title: Capture photo
data_tool: kyc.photo
permissions: [camera]
"#,
                Value::Null,
            ),
            (
                r#"
id: voice
kind: audio_recorder
title: Record a memo
data_tool: notes.audio
permissions: [microphone]
"#,
                Value::Null,
            ),
        ];

        let mut index = Vec::new();
        for (yaml, result) in specs {
            let cfg = app(yaml);
            let compiled = compile_app(&cfg, None, &no_tools());
            std::fs::write(dir.join(format!("{}.html", cfg.id)), &compiled.html).unwrap();
            std::fs::write(
                dir.join(format!("{}.result.json", cfg.id)),
                serde_json::to_vec_pretty(result).unwrap(),
            )
            .unwrap();
            index.push(json!({
                "id": cfg.id,
                "kind": serde_json::to_value(cfg.kind).unwrap(),
                "title": cfg.title,
                "has_data": !result.is_null(),
            }));
        }
        std::fs::write(
            dir.join("index.json"),
            serde_json::to_vec_pretty(&json!({ "apps": index })).unwrap(),
        )
        .unwrap();
        eprintln!("dumped {} apps to {}", specs.len(), dir.display());
    }

    #[test]
    fn compiles_uri_html_and_meta() {
        let cfg = app(r#"
id: customers
kind: table
title: Customers
data_tool: crm.list
columns:
  - { field: $.name, header: Name }
  - { field: $.balance, header: Balance, format: currency, align: end }
row_actions:
  - { id: open, label: Open, tool: crm.get, arg_map: { id: $.id } }
primary_action: open
"#);
        let compiled = compile_app(&cfg, None, &no_tools());
        assert_eq!(compiled.uri, "ui://mcpg/customers");
        assert_eq!(
            compiled.descriptor_meta["ui"]["resourceUri"],
            "ui://mcpg/customers"
        );
        // the shell marker is gone and the data island is present
        assert!(!compiled.html.contains(CONFIG_MARKER));
        assert!(
            compiled
                .html
                .contains(r#"<script type="application/json" id="mcpg-app-config">"#)
        );
        // the binding round-trips out of the island
        let island = extract_island(&compiled.html);
        let parsed: Value = serde_json::from_str(&island).unwrap();
        assert_eq!(parsed["kind"], "table");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["columns"][1]["format"], "currency");
        assert_eq!(parsed["primary_action"], "open");
    }

    #[test]
    fn window_config_drops_credential_surface() {
        let cfg = app(r#"
id: pv
kind: detail
title: PV
data_tool: t.get
allow_credential_values: true
public_values: { token: "cred://vault/x" }
"#);
        let wc = build_window_config(&cfg, &no_tools());
        assert!(wc.get("public_values").is_none());
        assert!(wc.get("allow_credential_values").is_none());
        // and therefore the island can never carry the secret reference
        let html = render_html(&wc);
        assert!(!html.contains("cred://"));
    }

    #[test]
    fn plain_public_values_are_injected_secret_refs_dropped() {
        let cfg = app(r#"
id: pv
kind: map
title: Map
data_tool: geo.list
allow_credential_values: true
map: { lat_field: $.lat, lng_field: $.lng }
public_values:
  tile_token: "pk.public-token"
  leaked: "vault://secret/x"
"#);
        let wc = build_window_config(&cfg, &no_tools());
        let pv = wc["public_values"].as_object().unwrap();
        assert_eq!(
            pv.get("tile_token").and_then(|v| v.as_str()),
            Some("pk.public-token")
        );
        // the secret-ref entry is dropped (resolution not wired)
        assert!(pv.get("leaked").is_none());
        assert!(wc.get("allow_credential_values").is_none());
    }

    #[test]
    fn data_island_escapes_script_breakout() {
        // a hostile column header containing </script> and markup
        let cfg = app(
            "id: x\nkind: table\ntitle: \"</script><img src=x onerror=alert(1)>\"\ndata_tool: t.list\n",
        );
        let html = render_html(&build_window_config(&cfg, &no_tools()));
        // no raw closing tag / angle brackets leaked from the binding
        assert!(!html.contains("</script><img"));
        assert!(html.contains("\\u003c/script\\u003e"));
        // still valid JSON once unescaped by a parser
        let parsed: Value = serde_json::from_str(&extract_island(&html)).unwrap();
        assert_eq!(parsed["title"], "</script><img src=x onerror=alert(1)>");
    }

    #[test]
    fn descriptor_meta_is_clamped_by_policy() {
        let cfg = app(r#"
id: m
kind: table
title: M
data_tool: t.list
csp: { connect_domains: ["api.example.com", "evil.com"] }
"#);
        let policy = AppsPolicy {
            connect_domains: vec!["api.example.com".to_owned()],
            resource_domains: vec!["*".to_owned()],
            frame_domains: vec!["self".to_owned()],
            base_uri_domains: vec!["self".to_owned()],
            redirect_domains: vec!["*".to_owned()],
            allowed_permissions: vec![],
            allowed_domains: None,
            strict: false,
        };
        let compiled = compile_app(&cfg, Some(&policy), &no_tools());
        assert_eq!(
            compiled.descriptor_meta["ui"]["csp"]["connectDomains"],
            json!(["api.example.com"])
        );
    }

    #[test]
    fn descriptor_carries_ui_mime_and_meta() {
        let cfg = app("id: d\nkind: list\ntitle: D\ndata_tool: t.list\n");
        let d = compile_app(&cfg, None, &no_tools()).to_descriptor();
        assert_eq!(d.uri, "ui://mcpg/d");
        assert_eq!(d.mime_type.as_deref(), Some(UI_MIME_TYPE));
        assert!(d.meta.is_some());
    }

    #[test]
    fn introspects_table_columns_from_output_schema() {
        let cfg = app("id: c\nkind: table\ntitle: C\ndata_tool: crm.list\n");
        let io = ToolIo {
            input_schema: None,
            output_schema: Some(json!({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "balance": { "type": "number" },
                                "created_at": { "type": "string", "format": "date-time" }
                            }
                        }
                    }
                }
            })),
        };
        let wc = build_window_config(&cfg, &tools_with("crm.list", io));
        let cols = wc["columns"].as_array().unwrap();
        assert_eq!(cols.len(), 3);
        // derived field + titlecased header + inferred format
        let by_field = |f: &str| {
            cols.iter()
                .find(|c| c["field"] == json!(f))
                .unwrap()
                .clone()
        };
        assert_eq!(by_field("$.name")["header"], "Name");
        assert_eq!(by_field("$.balance")["format"], "number");
        assert_eq!(by_field("$.created_at")["header"], "Created At");
        assert_eq!(by_field("$.created_at")["format"], "date");
    }

    #[test]
    fn explicit_columns_win_over_introspection() {
        let cfg = app(
            "id: c\nkind: table\ntitle: C\ndata_tool: crm.list\ncolumns:\n  - { field: $.only, header: Only }\n",
        );
        let io = ToolIo {
            input_schema: None,
            output_schema: Some(json!({
                "type": "array",
                "items": { "type": "object", "properties": { "a": {}, "b": {} } }
            })),
        };
        let wc = build_window_config(&cfg, &tools_with("crm.list", io));
        let cols = wc["columns"].as_array().unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0]["field"], "$.only");
    }

    #[test]
    fn introspects_form_fields_from_input_schema() {
        let cfg = app("id: f\nkind: form\ntitle: F\ndata_tool: crm.create\n");
        let io = ToolIo {
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "customer_name": { "type": "string", "title": "Customer" },
                    "amount": { "type": "number" }
                }
            })),
            output_schema: None,
        };
        let wc = build_window_config(&cfg, &tools_with("crm.create", io));
        let fields = wc["fields"].as_array().unwrap();
        // form fields use the bare input arg name + title-or-titlecase label
        let f0 = fields
            .iter()
            .find(|f| f["field"] == json!("customer_name"))
            .unwrap();
        assert_eq!(f0["label"], "Customer");
        let f1 = fields
            .iter()
            .find(|f| f["field"] == json!("amount"))
            .unwrap();
        assert_eq!(f1["label"], "Amount");
    }

    #[test]
    fn introspection_noop_without_schema_or_tool() {
        let cfg = app("id: c\nkind: table\ntitle: C\ndata_tool: missing.tool\n");
        let wc = build_window_config(&cfg, &no_tools());
        assert!(wc.get("columns").is_none());
    }

    #[test]
    fn introspection_skips_keys_that_break_the_json_path() {
        let cfg = app("id: c\nkind: table\ntitle: C\ndata_tool: t.list\n");
        let io = ToolIo {
            input_schema: None,
            output_schema: Some(json!({
                "type": "array",
                "items": { "type": "object", "properties": { "ok": {}, "a.b": {}, "": {} } }
            })),
        };
        let wc = build_window_config(&cfg, &tools_with("t.list", io));
        let cols = wc["columns"].as_array().unwrap();
        // dotted key (mis-splits client JSON-path) and empty key are skipped
        assert_eq!(cols.len(), 1);
        assert_eq!(cols[0]["field"], "$.ok");
    }

    #[test]
    fn cache_token_is_stable_and_content_bound() {
        let cfg = app("id: c\nkind: table\ntitle: C\ndata_tool: t.list\n");
        let a = compile_app(&cfg, None, &no_tools());
        let b = compile_app(&cfg, None, &no_tools());
        assert_eq!(a.cache_token, b.cache_token); // stable for identical content
        assert_eq!(a.cache_token.len(), 16);
        let cfg2 = app("id: c\nkind: table\ntitle: Changed\ndata_tool: t.list\n");
        let c = compile_app(&cfg2, None, &no_tools());
        assert_ne!(a.cache_token, c.cache_token); // changes when content changes
    }

    #[test]
    fn derived_columns_are_bounded() {
        let mut props = serde_json::Map::new();
        for i in 0..250 {
            props.insert(format!("f{i}"), json!({ "type": "string" }));
        }
        let cfg = app("id: c\nkind: table\ntitle: C\ndata_tool: t.list\n");
        let io = ToolIo {
            input_schema: None,
            output_schema: Some(
                json!({ "type": "array", "items": { "type": "object", "properties": props } }),
            ),
        };
        let wc = build_window_config(&cfg, &tools_with("t.list", io));
        assert_eq!(wc["columns"].as_array().unwrap().len(), 100); // MAX_DERIVED_FIELDS
    }

    #[test]
    fn app_tool_names_are_namespaced() {
        let cfg = app(
            "id: board\nkind: table\ntitle: B\ndata_tool: t.list\napp_tools:\n  - { name: get_selected, source: selection }\n",
        );
        let wc = build_window_config(&cfg, &no_tools());
        assert_eq!(wc["app_tools"][0]["name"], "app.board.get_selected");
        assert_eq!(wc["app_tools"][0]["source"], "selection");
    }

    #[test]
    fn key_value_introspects_fields_like_detail() {
        let cfg = app("id: k\nkind: key_value\ntitle: K\ndata_tool: t.get\n");
        let io = ToolIo {
            input_schema: None,
            output_schema: Some(json!({
                "type": "object",
                "properties": { "a": { "type": "string" }, "b": { "type": "number" } }
            })),
        };
        let wc = build_window_config(&cfg, &tools_with("t.get", io));
        assert_eq!(wc["fields"].as_array().unwrap().len(), 2);
    }

    fn extract_island(html: &str) -> String {
        let open = r#"<script type="application/json" id="mcpg-app-config">"#;
        let start = html.find(open).unwrap() + open.len();
        let end = html[start..].find("</script>").unwrap() + start;
        // reverse the script-escaping the serializer applied
        html[start..end]
            .replace("\\u003c", "<")
            .replace("\\u003e", ">")
            .replace("\\u0026", "&")
            .replace("\\u2028", "\u{2028}")
            .replace("\\u2029", "\u{2029}")
    }
}
