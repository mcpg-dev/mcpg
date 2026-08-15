//! [`ContentStoreRegistry`] — id-keyed multi-provider map of
//! configured content stores, plus the per-binding routing rules that
//! say which binding maps to which storage provider.
//!
//! Operators declare named providers at the top level of their config:
//!
//! ```yaml
//! storage:
//!   default: media
//!   providers:
//!     - id: default
//!       kind: in_process
//!       config: { max_bytes: 268435456 }
//!     - id: media
//!       kind: s3
//!       config: { bucket: mcpg-media, region: us-east-1 }
//! ```
//!
//! Each binding entry declares which provider to use:
//!
//! ```yaml
//! bindings:
//!   - name: dalle
//!     type: openai_image
//!     storage: media     # picks "media" from the registry
//!     spec: { ... }
//! ```
//!
//! Bindings without an explicit `storage:` field fall back to the
//! provider id named in `storage.default` (or the conventional id
//! `default` when neither is set). The gateway auto-creates an
//! in-process provider with id `default` if the operator declared
//! no providers AND no binding asked for a specific one.
//!
//! See `mcp_gateway_llm_phase_5_rfc.md` §7 for the full design.

use std::collections::HashMap;
use std::sync::Arc;

use mcpg_backend_llm_shared::ContentStore;

/// The conventional storage provider id used when a binding doesn't
/// declare its own `storage:` field AND `storage.default` is unset.
pub const DEFAULT_STORAGE_ID: &str = "default";

/// Multi-provider content store registry, plus the binding-name →
/// storage-id routing rules and the operator-configured default-id.
#[derive(Clone)]
pub struct ContentStoreRegistry {
    stores: HashMap<String, Arc<dyn ContentStore>>,
    binding_routes: HashMap<String, String>,
    /// Provider id bindings without an explicit `storage:` route fall
    /// back to. Resolved at boot from `storage.default` or the
    /// conventional [`DEFAULT_STORAGE_ID`].
    default_id: String,
}

impl std::fmt::Debug for ContentStoreRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentStoreRegistry")
            .field("stores", &self.stores.keys().collect::<Vec<_>>())
            .field("binding_routes", &self.binding_routes)
            .field("default_id", &self.default_id)
            .finish()
    }
}

impl ContentStoreRegistry {
    pub fn new(
        stores: HashMap<String, Arc<dyn ContentStore>>,
        binding_routes: HashMap<String, String>,
        default_id: String,
    ) -> Self {
        Self {
            stores,
            binding_routes,
            default_id,
        }
    }

    /// The default provider id — what bindings without an explicit
    /// `storage:` route fall back to and what the URI scheme elides
    /// in the bare form.
    pub fn default_id(&self) -> &str {
        &self.default_id
    }

    /// Resolve the storage provider for a given binding name. Returns
    /// the routed provider when one is configured for `backend_name`,
    /// otherwise falls back to [`Self::default_id`]. Returns `None`
    /// only when neither the routed id nor the default is registered
    /// (operator misconfiguration; gateway should have caught it at
    /// boot, but the type-system can't enforce that statically).
    pub fn for_binding(&self, backend_name: &str) -> Option<&Arc<dyn ContentStore>> {
        let id = self
            .binding_routes
            .get(backend_name)
            .map(String::as_str)
            .unwrap_or(&self.default_id);
        self.stores.get(id)
    }

    /// The provider id a given binding routes to. Used to encode
    /// the storage prefix in the `mcpg-resource://<id>/<resource>`
    /// URI scheme.
    pub fn storage_id_for_binding(&self, backend_name: &str) -> &str {
        self.binding_routes
            .get(backend_name)
            .map(String::as_str)
            .unwrap_or(&self.default_id)
    }

    /// Direct lookup by provider id. Used by the `resources/read`
    /// handler when parsing `mcpg-resource://<id>/<resource>`.
    pub fn by_id(&self, id: &str) -> Option<&Arc<dyn ContentStore>> {
        self.stores.get(id)
    }

    /// Iterator over `(id, store)` pairs. Used by the background
    /// TTL-sweep task to call `sweep_expired()` on every backend.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<dyn ContentStore>)> {
        self.stores.iter()
    }

    /// Whether the registry has the operator-configured default
    /// provider registered. Boot-time invariant — should always be
    /// true once the gateway is running.
    pub fn has_default(&self) -> bool {
        self.stores.contains_key(&self.default_id)
    }

    /// Number of registered storage providers.
    pub fn len(&self) -> usize {
        self.stores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    /// Format a `mcpg-resource://<id>/<resource>` URI given a provider
    /// id and a resource id. The operator-configured default provider
    /// uses the bare-resource form for back-compat with clients that
    /// already speak the legacy URI scheme.
    pub fn format_resource_uri(&self, storage_id: &str, resource_id: &str) -> String {
        if storage_id == self.default_id {
            format!("mcpg-resource://{resource_id}")
        } else {
            format!("mcpg-resource://{storage_id}/{resource_id}")
        }
    }

    /// Parse a `mcpg-resource://<id>/<resource>` URI (or the bare
    /// `mcpg-resource://<resource>` legacy form, which resolves to
    /// the operator-configured default provider). Accepts the bare
    /// resource id (`hash:abc…` / `alias:s:n`) too.
    ///
    /// Returns `(storage_id, resource_id)`. The `resource_id` is the
    /// value the underlying `ContentStore::get` expects (i.e. with
    /// `hash:` / `alias:` prefix preserved, or bare hex if that's
    /// what was stored).
    pub fn parse_resource_uri(&self, uri_or_id: &str) -> (String, String) {
        let body = uri_or_id
            .strip_prefix("mcpg-resource://")
            .unwrap_or(uri_or_id);

        if let Some((maybe_storage, rest)) = body.split_once('/')
            && !maybe_storage.contains(':')
            && !maybe_storage.is_empty()
        {
            return (maybe_storage.to_owned(), rest.to_owned());
        }
        (self.default_id.clone(), body.to_owned())
    }

    /// Drain every built content-store profile on gateway
    /// shutdown / reload. The plugin-host `PluginRegistry::shutdown_all`
    /// drains the content-store *factories* (`ContentStorePlugin`), but the
    /// live profile instances built via `build_profile` live here and were
    /// never shut down — every other plugin class gets a final
    /// `shutdown()`, so this one should too. `ContentStore::shutdown`
    /// defaults to a no-op (in-process / file providers do nothing); a
    /// stateful provider (e.g. an S3 multipart buffer) gets its flush.
    /// Each store is bounded by `per_store_timeout` so a wedged provider
    /// cannot stall teardown. Stores may be `Arc`-shared across profile ids
    /// (the same backend mapped under several names); de-dup by pointer so
    /// `shutdown()` fires once per distinct instance.
    pub async fn shutdown(&self, per_store_timeout: std::time::Duration) {
        // De-dup Arc-shared stores by pointer in a SYNC pass, then drain.
        // The raw pointers used for de-dup are `!Send`, so they must not be
        // held across an `.await` (that would make this future `!Send` and
        // break the gateway shutdown/reload tasks) — scope them so they drop
        // before the drain loop, which carries only owned `(String, Arc)`.
        let distinct: Vec<(String, Arc<dyn ContentStore>)> = {
            let mut seen: Vec<*const ()> = Vec::new();
            let mut out = Vec::new();
            for (id, store) in &self.stores {
                let ptr = Arc::as_ptr(store) as *const ();
                if !seen.contains(&ptr) {
                    seen.push(ptr);
                    out.push((id.clone(), Arc::clone(store)));
                }
            }
            out
        };
        for (id, store) in distinct {
            if tokio::time::timeout(per_store_timeout, store.shutdown())
                .await
                .is_err()
            {
                tracing::warn!(
                    storage_id = %id,
                    "content_store shutdown exceeded budget; abandoning"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with(default_id: &str) -> ContentStoreRegistry {
        let store: Arc<dyn ContentStore> =
            mcpg_backend_llm_shared::InProcessContentStore::new(1024);
        let mut stores = HashMap::new();
        stores.insert("default".into(), store.clone());
        stores.insert("media".into(), store);
        let mut routes = HashMap::new();
        routes.insert("dalle".into(), "media".into());
        ContentStoreRegistry::new(stores, routes, default_id.to_owned())
    }

    /// A `ContentStore` that records how many times `shutdown()` fired —
    /// used to prove the drain actually reaches each distinct store
    /// once (in-process / file stores have a no-op shutdown, so the real
    /// store can't demonstrate this).
    #[derive(Debug)]
    struct ShutdownCountingStore(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    #[async_trait::async_trait]
    impl ContentStore for ShutdownCountingStore {
        async fn put(
            &self,
            _content: mcpg_plugin_protocol::content_store::ContentToStore,
        ) -> Result<
            mcpg_plugin_protocol::content_store::ResourceHandle,
            mcpg_plugin_protocol::content_store::ContentStoreError,
        > {
            unimplemented!("test store: put unused")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<
            Option<mcpg_plugin_protocol::content_store::ResourceContent>,
            mcpg_plugin_protocol::content_store::ContentStoreError,
        > {
            Ok(None)
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<(), mcpg_plugin_protocol::content_store::ContentStoreError> {
            Ok(())
        }
        async fn signed_url(
            &self,
            _id: &str,
            _ttl: std::time::Duration,
        ) -> Result<Option<String>, mcpg_plugin_protocol::content_store::ContentStoreError>
        {
            Ok(None)
        }
        fn stats(&self) -> mcpg_plugin_protocol::content_store::ContentStoreStats {
            Default::default()
        }
        async fn shutdown(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_drains_each_distinct_store_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Two distinct stores + one Arc-shared across two ids: shutdown must
        // fire once per DISTINCT instance (3 ids, 2 distinct stores → 2 calls).
        let count = Arc::new(AtomicUsize::new(0));
        let a: Arc<dyn ContentStore> = Arc::new(ShutdownCountingStore(count.clone()));
        let b: Arc<dyn ContentStore> = Arc::new(ShutdownCountingStore(count.clone()));
        let mut stores = HashMap::new();
        stores.insert("default".to_string(), a.clone());
        stores.insert("alias-of-default".to_string(), a); // shares the same Arc as default
        stores.insert("media".to_string(), b);
        let registry = ContentStoreRegistry::new(stores, HashMap::new(), "default".into());

        registry.shutdown(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "each distinct store drained exactly once (Arc-shared ids de-duped)"
        );
    }

    #[test]
    fn parse_bare_id_resolves_to_default() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let (storage, id) = registry.parse_resource_uri("mcpg-resource://hash:abc");
        assert_eq!(storage, DEFAULT_STORAGE_ID);
        assert_eq!(id, "hash:abc");
    }

    #[test]
    fn parse_storage_prefix() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let (storage, id) = registry.parse_resource_uri("mcpg-resource://media/hash:abc");
        assert_eq!(storage, "media");
        assert_eq!(id, "hash:abc");
    }

    #[test]
    fn parse_alias_with_storage() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let (storage, id) =
            registry.parse_resource_uri("mcpg-resource://media/alias:sess-1:incident");
        assert_eq!(storage, "media");
        assert_eq!(id, "alias:sess-1:incident");
    }

    #[test]
    fn parse_alias_without_storage_uses_default() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let (storage, id) = registry.parse_resource_uri("mcpg-resource://alias:sess-1:incident");
        assert_eq!(storage, DEFAULT_STORAGE_ID);
        assert_eq!(id, "alias:sess-1:incident");
    }

    #[test]
    fn parse_accepts_bare_id_without_scheme() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let (storage, id) = registry.parse_resource_uri("hash:abc");
        assert_eq!(storage, DEFAULT_STORAGE_ID);
        assert_eq!(id, "hash:abc");
    }

    #[test]
    fn format_default_emits_bare_form() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let uri = registry.format_resource_uri(DEFAULT_STORAGE_ID, "hash:abc");
        assert_eq!(uri, "mcpg-resource://hash:abc");
    }

    #[test]
    fn format_named_storage_includes_prefix() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        let uri = registry.format_resource_uri("media", "hash:abc");
        assert_eq!(uri, "mcpg-resource://media/hash:abc");
    }

    #[test]
    fn operator_default_elides_prefix() {
        // Operator picked "media" as the default; URIs for assets in
        // "media" should emit the bare form.
        let registry = registry_with("media");
        let uri = registry.format_resource_uri("media", "hash:abc");
        assert_eq!(uri, "mcpg-resource://hash:abc");
        let uri = registry.format_resource_uri("default", "hash:abc");
        assert_eq!(uri, "mcpg-resource://default/hash:abc");
    }

    #[test]
    fn operator_default_resolves_bare_to_picked_id() {
        let registry = registry_with("media");
        let (storage, id) = registry.parse_resource_uri("mcpg-resource://hash:abc");
        assert_eq!(storage, "media");
        assert_eq!(id, "hash:abc");
    }

    #[test]
    fn registry_routes_known_binding() {
        let registry = registry_with(DEFAULT_STORAGE_ID);
        assert_eq!(registry.storage_id_for_binding("dalle"), "media");
        assert_eq!(registry.storage_id_for_binding("unknown"), "default");
        assert!(registry.for_binding("dalle").is_some());
        assert!(registry.for_binding("unknown").is_some());
        assert!(registry.has_default());
    }
}
