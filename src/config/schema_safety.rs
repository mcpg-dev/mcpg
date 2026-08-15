//! Boot-time JSON Schema hardening for tool input/output schemas.
//!
//! A tool descriptor's `inputSchema` / `outputSchema` is compiled into
//! a validator at boot and run against every call argument. Two hazards
//! follow from accepting an arbitrary operator- or plugin-supplied
//! schema unchecked:
//!
//! - **Fail-open validation.** A schema the compiler cannot build (a
//!   malformed shape, or one drawn from an unsupported JSON Schema
//!   dialect) silently leaves the tool with no validator, so it runs
//!   UNVALIDATED. This module turns that into a hard boot error so a
//!   broken schema fails closed rather than waving every argument
//!   through.
//! - **Schema-driven resource exhaustion / SSRF.** Per SEP-2106 a
//!   schema may use the full JSON Schema 2020-12 vocabulary, including
//!   `$ref` and the `allOf`/`anyOf`/`oneOf` composition keywords. An
//!   off-document `$ref` pointing at `http(s)`/`file` lets schema
//!   resolution reach off-box (SSRF); a deeply nested or very wide
//!   composition is a denial-of-service vector at validation time.
//!   This module bans network/file `$ref` and bounds composition
//!   depth/breadth + total node count.
//!
//! All checks are pure functions over `serde_json::Value`, invoked from
//! `AppConfig::validate_bindings` so they surface at `config validate`
//! and refuse boot.

use anyhow::Result;
use serde_json::Value;

/// Maximum nesting depth of `allOf`/`anyOf`/`oneOf` composition (and
/// nested object/array schemas) the gateway will compile. Schemas
/// nested deeper than this are rejected at boot — a legitimate tool
/// schema is shallow; deep nesting is a validation-time DoS vector.
pub const MAX_SCHEMA_DEPTH: usize = 32;

/// Maximum number of subschemas in a single `allOf`/`anyOf`/`oneOf`
/// array. A wide composition multiplies validation cost; a real tool
/// schema needs only a handful of branches.
pub const MAX_COMPOSITION_BREADTH: usize = 64;

/// Maximum total number of schema nodes (objects + array elements)
/// walked across the whole schema. Caps the aggregate size so a schema
/// that stays under the depth/breadth limits but is enormous overall is
/// still refused.
pub const MAX_SCHEMA_NODES: usize = 10_000;

/// The three JSON Schema composition keywords whose array breadth and
/// nesting depth this module bounds.
const COMPOSITION_KEYS: &[&str] = &["allOf", "anyOf", "oneOf"];

/// Validate a tool input/output schema for the safety posture above.
///
/// `path` is the operator-facing config path (e.g.
/// `bindings[3].input_schema`) used in error messages. Returns `Ok(())`
/// when the schema is safe to compile, or a descriptive error naming
/// the offending construct.
pub fn validate_tool_schema(schema: &Value, path: &str) -> Result<()> {
    let mut node_budget = MAX_SCHEMA_NODES;
    walk(schema, path, 0, &mut node_budget)
}

/// Retriever handed to every schema compilation in the gateway.
///
/// `jsonschema` is built with its default features, so the retriever it
/// would otherwise install fetches `http(s)` `$ref`s with
/// `reqwest::blocking` and opens `file:` ones — off-box reads from inside
/// the async boot/reload task, which additionally panics on the nested
/// runtime. [`validate_tool_schema`] already bans off-document `$ref`, so
/// nothing should reach here; refusing rather than fetching means a path
/// that skips that check cannot turn into an outbound request.
struct RefuseOffDocumentRefs;

impl jsonschema::Retrieve for RefuseOffDocumentRefs {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<&str>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!(
            "off-document schema reference '{uri}' is not resolvable: the gateway \
             does not fetch schemas over the network or from the filesystem during \
             compilation"
        )
        .into())
    }
}

/// Compile a schema after checking it against the safety posture above.
///
/// The single entry point for turning a schema into a validator: it runs
/// [`validate_tool_schema`] first and compiles with a retriever that
/// refuses to resolve anything off-document. Call this rather than
/// `jsonschema::validator_for`, so a new compile site cannot silently
/// arrive without the checks.
pub fn compile_checked(schema: &Value, path: &str) -> Result<jsonschema::Validator> {
    validate_tool_schema(schema, path)?;
    jsonschema::options()
        .with_retriever(RefuseOffDocumentRefs)
        .build(schema)
        .map_err(|e| anyhow::anyhow!("{path} is not a valid JSON Schema: {e}"))
}

fn walk(node: &Value, path: &str, depth: usize, node_budget: &mut usize) -> Result<()> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(anyhow::anyhow!(
            "{path}: JSON Schema nesting exceeds the {MAX_SCHEMA_DEPTH}-level depth bound; \
             a tool schema this deep is rejected as a validation-time DoS vector"
        ));
    }
    if *node_budget == 0 {
        return Err(anyhow::anyhow!(
            "{path}: JSON Schema exceeds the {MAX_SCHEMA_NODES}-node total-size bound"
        ));
    }
    *node_budget -= 1;

    match node {
        Value::Object(map) => {
            // Network / file `$ref` ban (SEP-2106): a `$ref` may point
            // within the document (`#/...`) but MUST NOT reach an
            // off-document `http(s)`/`file` location.
            if let Some(reference) = map.get("$ref").and_then(Value::as_str)
                && is_offdocument_ref(reference)
            {
                return Err(anyhow::anyhow!(
                    "{path}: JSON Schema `$ref` points off-document to '{reference}'; \
                     network and file `$ref` targets are banned (SSRF / supply-chain risk). \
                     Inline the schema or use the gateway `schema_registry` indirection."
                ));
            }
            for key in COMPOSITION_KEYS {
                if let Some(branches) = map.get(*key) {
                    let Some(arr) = branches.as_array() else {
                        return Err(anyhow::anyhow!(
                            "{path}: JSON Schema `{key}` must be an array of subschemas"
                        ));
                    };
                    if arr.len() > MAX_COMPOSITION_BREADTH {
                        return Err(anyhow::anyhow!(
                            "{path}: JSON Schema `{key}` has {} branches, exceeding the \
                             {MAX_COMPOSITION_BREADTH}-branch breadth bound",
                            arr.len()
                        ));
                    }
                }
            }
            for value in map.values() {
                walk(value, path, depth + 1, node_budget)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                walk(item, path, depth + 1, node_budget)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// True when a `$ref` string targets an off-document `http(s)` or
/// `file` location. In-document pointers (`#/...`), bare fragments, and
/// relative `$id`-anchor references are allowed; only an absolute
/// network/file URI is banned.
fn is_offdocument_ref(reference: &str) -> bool {
    let lower = reference.trim().to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("file://")
        || lower.starts_with("file:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plain_object_schema_passes() {
        let s = json!({ "type": "object", "properties": { "a": { "type": "string" } } });
        assert!(validate_tool_schema(&s, "t").is_ok());
    }

    #[test]
    fn compile_checked_builds_a_usable_validator() {
        let s = json!({ "type": "object", "required": ["a"], "properties": { "a": { "type": "string" } } });
        let v = compile_checked(&s, "t").expect("compiles");
        assert!(v.is_valid(&json!({ "a": "x" })));
        assert!(!v.is_valid(&json!({})));
    }

    #[test]
    fn compile_checked_refuses_an_off_document_ref() {
        for reference in [
            "http://169.254.169.254/latest/meta-data",
            "https://example.com/schema.json",
            "file:///etc/passwd",
        ] {
            let s = json!({ "type": "object", "properties": { "a": { "$ref": reference } } });
            assert!(
                compile_checked(&s, "t").is_err(),
                "accepted off-document ref {reference}"
            );
        }
    }

    #[test]
    fn compile_checked_does_not_fetch_when_a_ref_slips_past_the_ban() {
        // The ban keys on the `$ref` keyword. `$dynamicRef` reaches the
        // compiler's resolver by another route, and must not turn into an
        // outbound request: the retriever refuses instead of fetching.
        let s = json!({
            "type": "object",
            "properties": { "a": { "$dynamicRef": "https://example.com/nope.json#meta" } }
        });
        let err = compile_checked(&s, "t").expect_err("must not resolve off-document");
        let msg = err.to_string();
        assert!(
            msg.contains("not a valid JSON Schema") || msg.contains("not resolvable"),
            "got: {msg}"
        );
    }

    #[test]
    fn in_document_ref_is_allowed() {
        let s = json!({
            "type": "object",
            "properties": { "a": { "$ref": "#/$defs/Foo" } },
            "$defs": { "Foo": { "type": "string" } }
        });
        assert!(validate_tool_schema(&s, "t").is_ok());
    }

    #[test]
    fn https_ref_is_banned() {
        let s = json!({ "$ref": "https://evil.example/schema.json" });
        let err = validate_tool_schema(&s, "t").unwrap_err().to_string();
        assert!(err.contains("off-document"), "{err}");
    }

    #[test]
    fn http_ref_is_banned() {
        let s = json!({ "properties": { "x": { "$ref": "http://10.0.0.1/s" } } });
        assert!(validate_tool_schema(&s, "t").is_err());
    }

    #[test]
    fn file_ref_is_banned() {
        let s = json!({ "$ref": "file:///etc/passwd" });
        assert!(validate_tool_schema(&s, "t").is_err());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        // Build allOf nested deeper than MAX_SCHEMA_DEPTH.
        let mut node = json!({ "type": "object" });
        for _ in 0..(MAX_SCHEMA_DEPTH + 5) {
            node = json!({ "allOf": [node] });
        }
        assert!(validate_tool_schema(&node, "t").is_err());
    }

    #[test]
    fn wide_composition_is_rejected() {
        let branches: Vec<Value> = (0..(MAX_COMPOSITION_BREADTH + 1))
            .map(|_| json!({ "type": "object" }))
            .collect();
        let s = json!({ "anyOf": branches });
        let err = validate_tool_schema(&s, "t").unwrap_err().to_string();
        assert!(err.contains("breadth bound"), "{err}");
    }

    #[test]
    fn composition_must_be_array() {
        let s = json!({ "oneOf": { "type": "object" } });
        assert!(validate_tool_schema(&s, "t").is_err());
    }

    #[test]
    fn enormous_node_count_is_rejected() {
        // Wide-but-shallow object that blows the node budget.
        let mut props = serde_json::Map::new();
        for i in 0..(MAX_SCHEMA_NODES + 100) {
            props.insert(format!("p{i}"), json!({ "type": "string" }));
        }
        let s = json!({ "type": "object", "properties": Value::Object(props) });
        assert!(validate_tool_schema(&s, "t").is_err());
    }
}
