//! Apply the operator-configured `plugins.config_overlay` list at
//! gateway boot.
//!
//! Each URI in the overlay list is snapshotted via the
//! registered `config_provider` plugin bound to its scheme (set
//! up earlier in `build_plugin_registry`). Snapshots deep-merge
//! into an accumulator in order — later entries override
//! earlier ones. The final value is handed back to the caller
//! to stash on `AppState` so subsystems that migrate in
//! follow-up waves can query it.
//!
//! # Merge semantics
//!
//! Deep-merge on JSON objects:
//! - Same key on both sides + both values are objects → recurse.
//! - Same key on both sides + at least one non-object →
//!   replace wholesale (later wins).
//! - Key only on one side → carry through.
//!
//! Arrays are NOT merged element-wise; they replace wholesale.
//! Operators wanting per-element array merging structure their
//! overlays accordingly (e.g. a map keyed by id rather than an
//! array).

use mcpg_plugin_host::PluginRegistry;
use serde_json::Value;

/// Apply the operator's config-overlay list against the given
/// registry. Returns the merged JSON value (an empty object if
/// the operator configured no overlays). Fails at startup if
/// any URI's scheme isn't bound, the referenced backend is
/// unreachable, or the snapshot doesn't parse as JSON.
pub async fn apply_config_overlay(
    registry: &PluginRegistry,
    overlay_refs: &[String],
) -> Result<ConfigOverlayOutcome, anyhow::Error> {
    let mut merged = Value::Object(serde_json::Map::new());
    let mut versions: Vec<SourceVersion> = Vec::with_capacity(overlay_refs.len());

    for reference in overlay_refs {
        let snapshot = registry
            .snapshot_config(reference)
            .await
            .map_err(|e| anyhow::anyhow!("config overlay '{reference}' failed to snapshot: {e}"))?;
        versions.push(SourceVersion {
            reference: reference.clone(),
            version: snapshot.version.clone(),
            fetched_at: snapshot.fetched_at.clone(),
        });
        deep_merge(&mut merged, snapshot.values);
    }

    Ok(ConfigOverlayOutcome {
        merged,
        sources: versions,
    })
}

/// Deep-merge `overlay` onto `base` in place. Matches the
/// semantics documented at module level.
pub fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (base_slot, overlay_val) => {
            *base_slot = overlay_val;
        }
    }
}

/// Provenance for a single overlay source. Carries what the
/// audit event needs + what operators read from admin surfaces
/// to diagnose "which version of which source produced the
/// live overlay".
#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceVersion {
    pub reference: String,
    pub version: String,
    pub fetched_at: String,
}

/// Result of an overlay application.
#[derive(Debug, Clone)]
pub struct ConfigOverlayOutcome {
    pub merged: Value,
    pub sources: Vec<SourceVersion>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_merge_replaces_scalars() {
        let mut base = serde_json::json!({ "port": 7000 });
        deep_merge(&mut base, serde_json::json!({ "port": 8080 }));
        assert_eq!(base, serde_json::json!({ "port": 8080 }));
    }

    #[test]
    fn deep_merge_recurses_into_objects() {
        let mut base = serde_json::json!({
            "admin": { "port": 7000, "bind": "0.0.0.0" },
        });
        deep_merge(&mut base, serde_json::json!({ "admin": { "port": 8080 } }));
        assert_eq!(
            base,
            serde_json::json!({
                "admin": { "port": 8080, "bind": "0.0.0.0" },
            }),
            "sibling keys preserved; overlapping key replaced"
        );
    }

    #[test]
    fn deep_merge_replaces_arrays_wholesale() {
        let mut base = serde_json::json!({ "tags": ["a", "b"] });
        deep_merge(&mut base, serde_json::json!({ "tags": ["c"] }));
        assert_eq!(base, serde_json::json!({ "tags": ["c"] }));
    }

    #[test]
    fn deep_merge_adds_new_keys() {
        let mut base = serde_json::json!({ "a": 1 });
        deep_merge(&mut base, serde_json::json!({ "b": 2 }));
        assert_eq!(base, serde_json::json!({ "a": 1, "b": 2 }));
    }

    #[test]
    fn deep_merge_handles_object_to_scalar_replacement() {
        // If base has an object at `x` and overlay has a scalar
        // at `x`, overlay wins (scalar replaces object).
        let mut base = serde_json::json!({ "x": { "nested": true } });
        deep_merge(&mut base, serde_json::json!({ "x": 42 }));
        assert_eq!(base, serde_json::json!({ "x": 42 }));
    }

    #[test]
    fn deep_merge_handles_scalar_to_object_replacement() {
        // Symmetric: object replaces scalar.
        let mut base = serde_json::json!({ "x": 42 });
        deep_merge(&mut base, serde_json::json!({ "x": { "nested": true } }));
        assert_eq!(base, serde_json::json!({ "x": { "nested": true } }));
    }

    #[test]
    fn deep_merge_three_way_preserves_order_semantics() {
        // a then b then c: c's values win where they overlap.
        let mut acc = serde_json::json!({
            "feature_x": false,
            "tier": "free",
            "flags": { "dark_mode": true, "beta": false },
        });
        deep_merge(
            &mut acc,
            serde_json::json!({
                "tier": "pro",
                "flags": { "beta": true, "experimental": true },
            }),
        );
        deep_merge(
            &mut acc,
            serde_json::json!({
                "feature_x": true,
                "flags": { "dark_mode": false },
            }),
        );
        assert_eq!(
            acc,
            serde_json::json!({
                "feature_x": true,          // from layer 3
                "tier": "pro",              // from layer 2 (layer 3 didn't touch)
                "flags": {
                    "dark_mode": false,     // layer 3
                    "beta": true,           // layer 2 (layer 3 didn't touch)
                    "experimental": true,   // layer 2 (layer 3 didn't touch)
                },
            }),
        );
    }
}
