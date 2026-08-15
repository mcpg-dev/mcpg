//! Per-capability `store:` / `bus:` override configs.
//!
//! When an operator sets `<capability>.store: { kind, … }`
//! or `<capability>.bus: { kind, … }`, the gateway builds an
//! `Arc<dyn KeyValueStore>` / `Arc<dyn PubSub>` from that block instead
//! of inheriting from the `cluster:` plugin's primitive accessors.
//!
//! ## Recognised kinds
//!
//! - `cluster` — explicitly delegate to the
//!   cluster coordinator's primitive. Equivalent to omitting the
//!   override entirely (which still means "inherit from cluster"),
//!   but operator-visible. Carries no params.
//! - `memory` — in-process `MemoryKv` / `MemoryBus`. Single-node
//!   only.
//! - `file` — file-backed `FileKv` (KV only). Single-node persistent.
//!
//! Capabilities defaulting to `kind: cluster` is what makes
//! single-node deployments work out-of-the-box: `cluster:` itself
//! defaults to `kind: single_node` (built-in coordinator), so an
//! omitted override resolves to the in-process coordinator's
//! primitives.
//!
//! The recognised override kinds are in-process kinds only
//! (memory / file) — `redis` and `nats` are not valid override
//! kinds. Operators wanting redis-backed or nats-backed
//! capability state set `cluster.kind: redis | nats` and the
//! capability either inherits via `kind: cluster` or pins via an
//! in-process kind. Rationale: dropping the redis/nats override
//! kinds lets the gateway drop its `mcpg-state-{redis,nats}` path-
//! deps and centralise all backend-connection logic inside the
//! cluster plugins. The "sessions on redis-A, tasks on redis-B" use
//! case is no longer supported in-gateway; operators with that need
//! either run two MCPG deployments (one cluster.kind: redis each)
//! or wait for multi-cluster support.
//!
//! The serde shape mirrors `ClusterConfig`: a `kind: String`
//! discriminator plus a flattened `serde_json::Map` carrying the
//! kind-specific fields. The map
//! shape lets a kind grow new optional fields without churning
//! gateway code or operator yaml.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// `<capability>.store: { kind, … }` — produces an
/// `Arc<dyn mcpg_cluster_api::KeyValueStore>` at boot.
///
/// Recognised `kind` values: `cluster`, `memory`, `file`.
/// (`redis` and `nats` are not accepted here — set
/// `cluster.kind: redis | nats` and use `kind: cluster` here, or
/// omit the override entirely.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct StoreOverrideConfig {
    pub kind: String,
    #[serde(flatten, default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// `<capability>.bus: { kind, … }` — produces an
/// `Arc<dyn mcpg_cluster_api::PubSub>` at boot.
///
/// Recognised `kind` values: `cluster`, `memory`. (`redis` and
/// `nats` are not accepted here — set `cluster.kind: redis |
/// nats` and use `kind: cluster` here, or omit the override
/// entirely.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct BusOverrideConfig {
    pub kind: String,
    #[serde(flatten, default)]
    pub config: serde_json::Map<String, serde_json::Value>,
}

/// The meta-kind that delegates to the cluster coordinator's
/// primitive. Carries no params. An override with this kind
/// resolves identically to omitting the override entirely.
pub const CLUSTER_KIND: &str = "cluster";

// ---------------------------------------------------------------------------
// Per-kind typed parameter views
// ---------------------------------------------------------------------------
//
// These structs are the typed view boot-time builders deserialize the
// flattened `config` map into. Keeping them private means external
// callers see only the discriminator + raw map and the build-time
// failure mode is a single deserialise-with-serde error.

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterMetaParams {}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryStoreParams {}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileStoreParams {
    pub dir: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemoryBusParams {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl StoreOverrideConfig {
    /// True when this override delegates to the cluster coordinator's
    /// primitive. Equivalent to omitting the override entirely.
    #[must_use]
    pub fn is_cluster_meta(&self) -> bool {
        self.kind == CLUSTER_KIND
    }

    /// Boot-time validation: confirm `kind` is recognised and the
    /// kind-specific config block deserialises into the expected typed
    /// view. Catches typos and missing required fields before any
    /// connection attempt.
    ///
    /// Recognised forms:
    /// - `cluster` — delegate to the cluster coordinator's KV.
    /// - `memory` / `file` — built-in single-node primitives.
    /// - Reverse-domain plugin id (`dev.mcpg.kv.<name>`) — a
    ///   registered Store plugin. The plugin must be loaded by
    ///   the time the override resolves at boot (the plugin
    ///   lookup happens in `build_kv_from_override`); validation
    ///   here only checks the `kind` shape.
    /// - Short alias (e.g. `redis`) — expanded to
    ///   `dev.mcpg.kv.<alias>` and looked up in the registry.
    pub fn validate(&self) -> Result<()> {
        let value = serde_json::Value::Object(self.config.clone());
        match self.kind.as_str() {
            CLUSTER_KIND => {
                serde_json::from_value::<ClusterMetaParams>(value).map_err(|e| {
                    anyhow::anyhow!("invalid `cluster` store override (no params expected): {e}")
                })?;
            }
            "memory" => {
                serde_json::from_value::<MemoryStoreParams>(value)
                    .map_err(|e| anyhow::anyhow!("invalid `memory` store override: {e}"))?;
            }
            "file" => {
                serde_json::from_value::<FileStoreParams>(value)
                    .map_err(|e| anyhow::anyhow!("invalid `file` store override: {e}"))?;
            }
            "" => {
                return Err(anyhow::anyhow!("store override `kind:` must not be empty"));
            }
            // Plugin-id (reverse-domain) or short alias — defer
            // to `build_kv_from_override`'s registry lookup.
            // Config map is opaque; the plugin's own
            // deserialiser interprets it.
            _ => {}
        }
        Ok(())
    }
}

impl BusOverrideConfig {
    /// True when this override delegates to the cluster coordinator's
    /// primitive. Equivalent to omitting the override entirely.
    #[must_use]
    pub fn is_cluster_meta(&self) -> bool {
        self.kind == CLUSTER_KIND
    }

    pub fn validate(&self) -> Result<()> {
        let value = serde_json::Value::Object(self.config.clone());
        match self.kind.as_str() {
            CLUSTER_KIND => {
                serde_json::from_value::<ClusterMetaParams>(value).map_err(|e| {
                    anyhow::anyhow!("invalid `cluster` bus override (no params expected): {e}")
                })?;
            }
            "memory" => {
                serde_json::from_value::<MemoryBusParams>(value)
                    .map_err(|e| anyhow::anyhow!("invalid `memory` bus override: {e}"))?;
            }
            "redis" | "nats" => {
                return Err(anyhow::anyhow!(
                    "bus override kind '{}' is no longer supported as a \
                     per-capability override. Set `cluster.kind: {}` at \
                     the top level and use `kind: cluster` here (or omit \
                     the override entirely — same semantics).",
                    self.kind,
                    self.kind,
                ));
            }
            other => {
                return Err(anyhow::anyhow!(
                    "bus override kind '{other}' is not recognised. \
                     Valid kinds: cluster, memory. (For redis or nats, \
                     set `cluster.kind` instead — capabilities inherit \
                     automatically via `kind: cluster`.)"
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Typed-view extraction (used by app/mod.rs at boot)
// ---------------------------------------------------------------------------

impl StoreOverrideConfig {
    pub(crate) fn as_memory(&self) -> Result<MemoryStoreParams> {
        serde_json::from_value(serde_json::Value::Object(self.config.clone()))
            .map_err(|e| anyhow::anyhow!("invalid `memory` store override: {e}"))
    }

    pub(crate) fn as_file(&self) -> Result<FileStoreParams> {
        serde_json::from_value(serde_json::Value::Object(self.config.clone()))
            .map_err(|e| anyhow::anyhow!("invalid `file` store override: {e}"))
    }
}

impl BusOverrideConfig {
    pub(crate) fn as_memory(&self) -> Result<MemoryBusParams> {
        serde_json::from_value(serde_json::Value::Object(self.config.clone()))
            .map_err(|e| anyhow::anyhow!("invalid `memory` bus override: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(kind: &str, body: serde_json::Value) -> StoreOverrideConfig {
        let map = match body {
            serde_json::Value::Object(m) => m,
            _ => panic!("body must be object"),
        };
        StoreOverrideConfig {
            kind: kind.to_owned(),
            config: map,
        }
    }

    #[test]
    fn store_override_cluster_meta_kind_accepts_empty_config() {
        let o = cfg(CLUSTER_KIND, serde_json::json!({}));
        o.validate()
            .expect("cluster meta-kind valid with no fields");
        assert!(o.is_cluster_meta());
    }

    #[test]
    fn store_override_cluster_meta_kind_rejects_extra_fields() {
        let o = cfg(CLUSTER_KIND, serde_json::json!({"url": "x"}));
        let err = o.validate().unwrap_err().to_string();
        assert!(err.contains("cluster"), "{err}");
    }

    #[test]
    fn store_override_memory_is_not_cluster_meta() {
        let o = cfg("memory", serde_json::json!({}));
        assert!(!o.is_cluster_meta());
    }

    #[test]
    fn store_override_memory_accepts_empty_config() {
        let o = cfg("memory", serde_json::json!({}));
        o.validate().expect("memory valid with no fields");
        o.as_memory().expect("decodes");
    }

    #[test]
    fn store_override_file_requires_dir() {
        let o = cfg("file", serde_json::json!({}));
        let err = o.validate().unwrap_err().to_string();
        assert!(err.contains("file"), "{err}");
    }

    #[test]
    fn store_override_short_alias_passes_validation() {
        // Short aliases (`redis`, `nats`, `postgres`, …) and full
        // plugin ids
        // (`dev.mcpg.kv.<name>`) pass config-time validation;
        // resolution happens in `build_kv_from_override` where
        // the registry is consulted. Operators get a precise
        // error pointing at the missing plugin if the lookup
        // fails at boot — much better than a config-time
        // rejection that doesn't know what plugins are
        // available.
        let o = cfg("redis", serde_json::json!({"url": "redis://x"}));
        o.validate().expect("redis is now a permitted alias");

        let o = cfg("nats", serde_json::json!({"url": "nats://x"}));
        o.validate().expect("nats is now a permitted alias");

        let o = cfg("dev.mcpg.kv.dynamodb", serde_json::json!({}));
        o.validate().expect("full plugin id passes validation");
    }

    #[test]
    fn store_override_empty_kind_rejected() {
        let o = cfg("", serde_json::json!({}));
        let err = o.validate().unwrap_err().to_string();
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn store_override_file_typed_view() {
        let o = cfg("file", serde_json::json!({"dir": "/var/lib/mcpg/sessions"}));
        o.validate().expect("file valid");
        let typed = o.as_file().unwrap();
        assert_eq!(typed.dir, "/var/lib/mcpg/sessions");
    }

    #[test]
    fn store_override_file_unknown_field_rejected() {
        let o = cfg("file", serde_json::json!({"dir": "/x", "weird": "field"}));
        let err = o.validate().unwrap_err().to_string();
        assert!(
            err.contains("weird"),
            "deny_unknown_fields catches typos: {err}"
        );
    }

    #[test]
    fn bus_override_cluster_meta_kind_accepts_empty_config() {
        let m = BusOverrideConfig {
            kind: CLUSTER_KIND.into(),
            config: Default::default(),
        };
        m.validate().expect("cluster meta-kind valid for bus");
        assert!(m.is_cluster_meta());
    }

    #[test]
    fn bus_override_memory_only() {
        let m = BusOverrideConfig {
            kind: "memory".into(),
            config: Default::default(),
        };
        m.validate().expect("memory bus valid");
    }

    #[test]
    fn bus_override_redis_kind_rejected() {
        let r = BusOverrideConfig {
            kind: "redis".into(),
            config: serde_json::json!({"url": "redis://x"})
                .as_object()
                .unwrap()
                .clone(),
        };
        let err = r.validate().unwrap_err().to_string();
        assert!(err.contains("no longer supported"), "{err}");
        assert!(err.contains("cluster.kind: redis"), "{err}");
    }

    #[test]
    fn bus_override_nats_kind_rejected() {
        let n = BusOverrideConfig {
            kind: "nats".into(),
            config: Default::default(),
        };
        let err = n.validate().unwrap_err().to_string();
        assert!(err.contains("no longer supported"), "{err}");
        assert!(err.contains("cluster.kind: nats"), "{err}");
    }

    #[test]
    fn bus_override_rejects_file_kind() {
        let o = BusOverrideConfig {
            kind: "file".into(),
            config: Default::default(),
        };
        let err = o.validate().unwrap_err().to_string();
        assert!(err.contains("not recognised"), "{err}");
        assert!(err.contains("memory"), "{err}");
    }

    #[test]
    fn bus_override_memory_typed_view() {
        let m = BusOverrideConfig {
            kind: "memory".into(),
            config: Default::default(),
        };
        m.as_memory().expect("memory typed view");
    }
}
