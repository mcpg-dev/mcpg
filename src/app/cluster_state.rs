use super::*;

/// Cross-check that the installed cluster coordinator's slot-role
/// vocabulary agrees across its three representations, fail-closed.
/// The representations:
///
///  1. the live trait `ClusterBackend::cluster_provides()`,
///  2. the coordinator's manifest `provides` field, and
///  3. (built-in kinds only) the static wiring fallback table
///     `cluster_provides_for_kind`.
///
/// (1) and (2) are normally identical — the default `cluster_provides()`
/// derives from the manifest — but a coordinator MAY override the trait,
/// so we still assert it. (3) is what config-time validation and the
/// `mcpg-config` validator consult without a live instance; asserting it
/// here keeps the static table honest against the running coordinator.
/// For plugin-class (3rd-party) clusters the table is intentionally a
/// permissive catch-all, so the live set is authoritative and the table
/// is not compared.
pub(crate) fn cross_check_cluster_provides(
    coordinator: &dyn mcpg_cluster_api::ClusterBackend,
    cluster_kind: &str,
) -> anyhow::Result<()> {
    use std::collections::BTreeSet;
    let live: BTreeSet<String> = coordinator.cluster_provides();
    let manifest: BTreeSet<String> = coordinator.manifest().provides.iter().cloned().collect();
    if live != manifest {
        anyhow::bail!(
            "cluster coordinator '{}' role drift: cluster_provides()={:?} but \
             manifest `provides`={:?}; they must declare the same slot-role set \
             (cache/kv/bus)",
            coordinator.manifest().id,
            live,
            manifest,
        );
    }
    if crate::config::wiring::is_builtin_cluster_kind(cluster_kind) {
        let table: BTreeSet<String> =
            crate::config::wiring::cluster_provides_for_kind(cluster_kind)
                .into_iter()
                .map(str::to_owned)
                .collect();
        if live != table {
            anyhow::bail!(
                "cluster kind '{}' role drift: coordinator '{}' provides {:?} but the \
                 static wiring table (cluster_provides_for_kind) says {:?}; update \
                 the table arm so config-time validation matches the running coordinator",
                cluster_kind,
                coordinator.manifest().id,
                live,
                table,
            );
        }
    }
    Ok(())
}

/// Live boot-time reachability probe for a clustered (non-`single_node`)
/// coordinator. The vocabulary cross-check (`cross_check_cluster_provides`)
/// only proves the role *strings* agree; it never touches the coordinator,
/// so a coordinator that advertises `kv`/`bus` but cannot actually serve them
/// over the plugin FFI still passes and then silently de-clusters to
/// per-replica in-process state. This probe closes that gap: for every role
/// the coordinator advertises it (a) requires the matching primitive accessor
/// to be present and (b) does a live round-trip against it. A baseline
/// `node_info()` ping confirms the FFI is answering at all.
///
/// Fail-closed by default: on any failure the gateway refuses to boot, so a
/// clustered deployment never comes up silently de-clustered. The escape hatch
/// is `cluster.allow_degraded_boot: true`, which downgrades the hard failure
/// to a loud error log and lets the gateway start degraded (per-replica
/// state). `single_node` never reaches here (handled by the caller).
pub(crate) async fn probe_cluster_reachability(
    coordinator: &dyn mcpg_cluster_api::ClusterBackend,
    allow_degraded_boot: bool,
) -> anyhow::Result<()> {
    use bytes::Bytes;
    let id = coordinator.manifest().id.clone();
    let provides = coordinator.cluster_provides();

    // Run the probe and collect the first failure (if any). Each advertised
    // primitive must have a live accessor AND answer a round-trip.
    let probe = async {
        // Baseline FFI liveness: node_info must answer.
        let info = coordinator.node_info().await;
        if info.node_id.is_empty() {
            anyhow::bail!(
                "coordinator '{id}' node_info() returned an empty node_id — the coordinator \
                 FFI is not answering (placeholder/degraded response)"
            );
        }

        // KV role: accessor must exist and a put+get+delete must round-trip.
        if provides.contains("kv") {
            let Some(kv) = coordinator.key_value_store() else {
                anyhow::bail!(
                    "coordinator '{id}' advertises the `kv` role but exposes no \
                     key_value_store() accessor — clustered state would silently fall back to \
                     per-replica in-process MemoryKv"
                );
            };
            let probe_key = format!("mcpg:cluster:boot-probe:{}", uuid::Uuid::new_v4().simple());
            kv.put(
                &probe_key,
                Bytes::from_static(b"1"),
                Some(std::time::Duration::from_secs(30)),
            )
            .await
            .map_err(|e| anyhow::anyhow!("coordinator '{id}' KV put probe failed: {e}"))?;
            let got = kv
                .get(&probe_key)
                .await
                .map_err(|e| anyhow::anyhow!("coordinator '{id}' KV get probe failed: {e}"))?;
            if got.is_none() {
                anyhow::bail!(
                    "coordinator '{id}' KV get probe returned no value immediately after a \
                     put — the KV is not durable across the round-trip"
                );
            }
            // Best-effort cleanup; a delete failure here doesn't invalidate
            // the proven read-after-write, and the entry has a short TTL.
            let _ = kv.delete(&probe_key).await;
        }

        // Bus role: accessor must exist and a publish must round-trip. We do
        // not assert delivery (no second replica at boot) — a successful
        // publish proves the bus primitive reaches the coordinator.
        if provides.contains("bus") {
            let Some(bus) = coordinator.pub_sub() else {
                anyhow::bail!(
                    "coordinator '{id}' advertises the `bus` role but exposes no pub_sub() \
                     accessor — clustered delivery/cancellation/approval fan-out would \
                     silently fall back to a per-replica in-process MemoryBus"
                );
            };
            bus.publish("mcpg.cluster.boot-probe", Bytes::from_static(b"1"))
                .await
                .map_err(|e| anyhow::anyhow!("coordinator '{id}' bus publish probe failed: {e}"))?;
        }

        Ok::<(), anyhow::Error>(())
    };

    match probe.await {
        Ok(()) => {
            info!(
                cluster_plugin_id = %id,
                roles = ?provides,
                "cluster coordinator boot reachability probe OK"
            );
            Ok(())
        }
        Err(e) => {
            if allow_degraded_boot {
                tracing::error!(
                    cluster_plugin_id = %id,
                    "cluster coordinator boot reachability probe FAILED: {e}. \
                     cluster.allow_degraded_boot=true — starting DEGRADED (per-replica state, \
                     NOT shared across replicas). Cross-instance suspend/resume, sessions, and \
                     idempotency will NOT work cluster-wide."
                );
                Ok(())
            } else {
                Err(e.context(format!(
                    "cluster coordinator '{id}' failed the boot reachability probe; refusing to \
                     start clustered to avoid silent de-clustering. Fix the coordinator, or set \
                     cluster.allow_degraded_boot: true to boot degraded (per-replica state)"
                )))
            }
        }
    }
}

/// Cluster state-encryption context: the optional cipher plus the
/// operator's plaintext-tolerance flag. Built once from cluster config and
/// threaded into the capability KV/bus decorators (and the approvals
/// backstop) so the plaintext posture is uniform across every surface.
#[derive(Clone)]
pub(crate) struct StateEncryption {
    pub(crate) cipher:
        Option<std::sync::Arc<mcpg_plugin_host::credential_cache_cipher::EventCipher>>,
    pub(crate) allow_plaintext_reads: bool,
}

/// Build the opt-in cluster state-encryption context from the configured
/// env var. The cipher is `None` when `cluster.state_encryption_key_env`
/// is unset (plaintext). Errors if the env var is named but missing/empty
/// or the key is malformed: operator misconfiguration must fail loud at
/// boot, not silently ship plaintext.
pub(crate) fn build_state_cipher(
    cluster: &crate::config::ClusterConfig,
) -> Result<StateEncryption> {
    let allow_plaintext_reads = cluster.state_encryption_allow_plaintext_reads;
    let Some(env_name) = cluster.state_encryption_key_env.as_deref() else {
        return Ok(StateEncryption {
            cipher: None,
            allow_plaintext_reads,
        });
    };
    let key_b64 = std::env::var(env_name).map_err(|_| {
        anyhow::anyhow!(
            "cluster.state_encryption_key_env names env var `{env_name}` but it is unset/empty; \
             set it to a URL-safe-base64 32-byte key or remove the field"
        )
    })?;
    let kid = cluster
        .state_encryption_key_id
        .clone()
        .unwrap_or_else(|| "mcpg-cluster-state".to_owned());
    let cipher = mcpg_plugin_host::credential_cache_cipher::EventCipher::from_base64_key(
        key_b64.trim(),
        kid,
    )
    .map_err(|e| anyhow::anyhow!("cluster.state_encryption: invalid key in `{env_name}`: {e}"))?;
    info!(
        kid = %cipher.kid(),
        allow_plaintext_reads,
        "cluster state-encryption ENABLED — capability KV/bus state sealed with \
         XChaCha20-Poly1305 (plaintext reads rejected unless the migration flag is set)"
    );
    Ok(StateEncryption {
        cipher: Some(std::sync::Arc::new(cipher)),
        allow_plaintext_reads,
    })
}

/// Cluster-stable 32-byte secret derived from `cluster.state_encryption_key_env`,
/// or `None` when that env var is unset. This is the same key material
/// `build_state_cipher` consumes (URL-safe base64, padded or unpadded);
/// reading the raw bytes here lets the modern-resume key paths derive
/// domain-separated sub-keys that are IDENTICAL on every replica without an
/// operator configuring a second secret. Returns an error only when the env
/// var is named but unset/empty or the value is the wrong length — the same
/// fail-loud posture as `build_state_cipher`.
pub(crate) fn cluster_state_key_bytes(
    cluster: &crate::config::ClusterConfig,
) -> anyhow::Result<Option<[u8; 32]>> {
    use base64::Engine;
    let Some(env_name) = cluster.state_encryption_key_env.as_deref() else {
        return Ok(None);
    };
    let key_b64 = std::env::var(env_name).map_err(|_| {
        anyhow::anyhow!(
            "cluster.state_encryption_key_env names env var `{env_name}` but it is unset/empty"
        )
    })?;
    // Decode with the NO_PAD engine after stripping any trailing `=` so both a
    // canonically-padded and an unpadded URL-safe base64 key are accepted (the
    // pad-required `URL_SAFE` engine rejects the `=`-stripped string).
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(key_b64.trim().trim_end_matches('='))
        .map_err(|e| {
            anyhow::anyhow!(
                "cluster.state_encryption key in `{env_name}` is not URL-safe base64: {e}"
            )
        })?;
    if raw.len() != 32 {
        anyhow::bail!(
            "cluster.state_encryption key in `{env_name}` decoded to {} bytes, expected 32",
            raw.len()
        );
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(Some(key))
}

/// Derive a domain-separated 32-byte sub-key from a cluster-stable base key
/// via HMAC-SHA256. The `domain` string keeps each consumer's sub-key
/// independent (the modern-session key space is disjoint from the
/// requestState codec key space, etc.), so compromise/rotation reasoning is
/// per-domain. Reuses the existing HMAC primitive — no new crypto.
pub(crate) fn derive_cluster_subkey(base: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    hmac_sha256::HMAC::mac(domain, base)
}

/// Domain-separation label for the modern synthetic-session HMAC key derived
/// from the cluster-stable secret. Kept disjoint from the requestState codec
/// key space.
pub(crate) const SYNTHETIC_SESSION_KEY_DOMAIN: &[u8] = b"mcpg:modern-session-key:v1";

/// Wrap a resolved capability KV in the encrypting decorator when a
/// state cipher is configured; passthrough otherwise.
pub(crate) fn wrap_state_kv(
    kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    enc: &StateEncryption,
) -> std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> {
    match &enc.cipher {
        Some(c) => std::sync::Arc::new(
            mcpg_plugin_host::cluster_encryption::EncryptingKeyValueStore::new(kv, c.clone())
                .allow_plaintext_reads(enc.allow_plaintext_reads),
        ),
        None => kv,
    }
}

/// Wrap a resolved capability bus in the encrypting decorator when a
/// state cipher is configured; passthrough otherwise.
pub(crate) fn wrap_state_bus(
    bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>,
    enc: &StateEncryption,
) -> std::sync::Arc<dyn mcpg_cluster_api::PubSub> {
    match &enc.cipher {
        Some(c) => std::sync::Arc::new(
            mcpg_plugin_host::cluster_encryption::EncryptingPubSub::new(bus, c.clone())
                .allow_plaintext_reads(enc.allow_plaintext_reads),
        ),
        None => bus,
    }
}

/// Wrap a capability KV in the per-deployment tenant-prefix
/// decorator when `cluster.tenant_segment` is set; passthrough otherwise.
/// Applied OUTERMOST (after `wrap_state_kv`) so the cipher AAD binds
/// the full `t.<segment>/key` — cross-tenant swap-resistant.
pub(crate) fn wrap_tenant_kv(
    kv: std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>,
    segment: &Option<String>,
) -> std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> {
    match segment.as_deref() {
        Some(seg) => std::sync::Arc::new(
            mcpg_plugin_host::cluster_tenant::TenantPrefixKeyValueStore::new(kv, seg),
        ),
        None => kv,
    }
}

/// Tenant-prefix decorator for a capability bus; passthrough when
/// `cluster.tenant_segment` is unset. Applied outermost (after
/// `wrap_state_bus`).
pub(crate) fn wrap_tenant_bus(
    bus: std::sync::Arc<dyn mcpg_cluster_api::PubSub>,
    segment: &Option<String>,
) -> std::sync::Arc<dyn mcpg_cluster_api::PubSub> {
    match segment.as_deref() {
        Some(seg) => std::sync::Arc::new(
            mcpg_plugin_host::cluster_tenant::TenantPrefixPubSub::new(bus, seg),
        ),
        None => bus,
    }
}

/// Default `KeyValueStore` for a capability with no
/// `<capability>.store:` override. Inherits the cluster coordinator's
/// own `key_value_store()` accessor when one is available (single-node,
/// redis, nats), so every capability shares the cluster backbone's KV
/// by default. Falls back to a fresh in-process `MemoryKv` only when
/// the coordinator can't expose one.
pub(crate) fn default_capability_kv(
    capability: &str,
    coordinator: Option<&std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
) -> std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore> {
    use mcpg_cluster_api::KeyValueStore;
    use std::sync::Arc;
    if let Some(c) = coordinator {
        if let Some(kv) = c.key_value_store() {
            info!(
                capability,
                cluster_plugin_id = %c.manifest().id,
                "store: inherited from cluster coordinator"
            );
            return kv;
        }
        // Silent de-clustering guard: a coordinator IS installed
        // but exposes no key_value_store (consul/etcd never do; redis/nats
        // when unreachable at boot). With no per-capability `store:`
        // override, this capability silently falls back to in-process
        // MemoryKv — per-replica state with green readiness. WARN loudly so
        // a multi-replica operator sees the de-clustering rather than
        // discovering it in production.
        warn!(
            capability,
            cluster_plugin_id = %c.manifest().id,
            "store: cluster coordinator exposes no key_value_store — this capability \
             falls back to in-process MemoryKv and is NOT shared across replicas \
             (silent de-clustering). For real HA, set an explicit \
             `<capability>.store:` override (e.g. kind: redis) or use a coordinator \
             whose `provides` includes the `kv` role."
        );
        return Arc::new(crate::builtins::cluster_primitives::MemoryKv::new())
            as Arc<dyn KeyValueStore>;
    }
    info!(
        capability,
        "store: in-process MemoryKv (no cluster coordinator configured)"
    );
    Arc::new(crate::builtins::cluster_primitives::MemoryKv::new()) as Arc<dyn KeyValueStore>
}

/// Default `PubSub` for a bus with no `<bus>.bus:`
/// override. Mirrors `default_capability_kv`: prefer the cluster
/// coordinator's `pub_sub()` accessor; fall back to a fresh in-process
/// `MemoryBus` only when unavailable.
pub(crate) fn default_capability_bus(
    capability: &str,
    coordinator: Option<&std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
) -> std::sync::Arc<dyn mcpg_cluster_api::PubSub> {
    use mcpg_cluster_api::PubSub;
    use std::sync::Arc;
    if let Some(c) = coordinator {
        if let Some(bus) = c.pub_sub() {
            info!(
                capability,
                cluster_plugin_id = %c.manifest().id,
                "bus: inherited from cluster coordinator"
            );
            return bus;
        }
        // Silent de-clustering guard: a coordinator IS installed
        // but exposes no pub_sub (consul/etcd never do; redis exposes one,
        // nats when reachable). With no `<capability>.bus:` override the
        // bus silently falls back to an in-process MemoryBus — so
        // server→client delivery / cancellation / approval fan-out stays
        // per-replica. WARN loudly.
        warn!(
            capability,
            cluster_plugin_id = %c.manifest().id,
            "bus: cluster coordinator exposes no pub_sub — this capability falls back \
             to in-process MemoryBus and is NOT shared across replicas (silent \
             de-clustering). For real HA, set an explicit `<capability>.bus:` override \
             or use a coordinator whose `provides` includes the `bus` role."
        );
        return Arc::new(crate::builtins::cluster_primitives::MemoryBus::new()) as Arc<dyn PubSub>;
    }
    info!(
        capability,
        "bus: in-process MemoryBus (no cluster coordinator configured)"
    );
    Arc::new(crate::builtins::cluster_primitives::MemoryBus::new()) as Arc<dyn PubSub>
}

// ---------------------------------------------------------------------------
// Per-capability store/bus override resolvers
// ---------------------------------------------------------------------------
//
// These helpers turn a `<capability>.store: { kind, … }` /
// `<capability>.bus: { kind, … }` block into a concrete
// `Arc<dyn KeyValueStore>` / `Arc<dyn PubSub>` at boot. Each
// override carries its own connection details (URL, credentials,
// prefixes), so two capabilities pointing at different override
// blocks open separate connection pools — by design, and the only
// way for an operator to express "sessions over redis-A, tasks over
// redis-B" without forking the cluster plugin.
//
// Boot first checks for an override on the capability; if present it
// goes through these resolvers, otherwise the capability inherits the
// cluster coordinator's primitive (or a fresh in-process Memory*).

/// Resolve a per-capability `store:` override into an
/// `Arc<dyn KeyValueStore>`. Treats both an absent override and
/// `kind: cluster` as "use the cluster coordinator's primitive."
///
/// `kind: cluster` is a first-class override kind so operators can opt
/// into the cluster's KV explicitly (the YAML self-documents which
/// capabilities ride the cluster vs which are pinned). Resolution rules:
/// - `over` is `None` → use cluster's primitive (default).
/// - `over.kind == "cluster"` → use cluster's primitive (explicit).
/// - `over.kind` is `memory` / `file` → build the in-process backend.
/// - any other kind is rejected by `validate()` upstream.
pub(crate) async fn resolve_capability_kv(
    over: Option<&crate::config::StoreOverrideConfig>,
    capability: &str,
    coordinator: Option<&std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
    role: mcpg_plugin_protocol::store::StoreRole,
) -> anyhow::Result<std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>> {
    match over {
        None => Ok(default_capability_kv(capability, coordinator)),
        Some(o) if o.is_cluster_meta() => {
            o.validate()?;
            info!(
                capability,
                "store: explicit kind=cluster — inherits from cluster coordinator"
            );
            Ok(default_capability_kv(capability, coordinator))
        }
        Some(o) => build_kv_from_override(o, plugin_registry, role).await,
    }
}

/// Resolve a per-capability `bus:` override into an
/// `Arc<dyn PubSub>`. Treats both an absent override and
/// `kind: cluster` as "use the cluster coordinator's primitive."
pub(crate) async fn resolve_capability_bus(
    over: Option<&crate::config::BusOverrideConfig>,
    capability: &str,
    coordinator: Option<&std::sync::Arc<dyn mcpg_cluster_api::ClusterBackend>>,
) -> anyhow::Result<std::sync::Arc<dyn mcpg_cluster_api::PubSub>> {
    match over {
        None => Ok(default_capability_bus(capability, coordinator)),
        Some(o) if o.is_cluster_meta() => {
            o.validate()?;
            info!(
                capability,
                "bus: explicit kind=cluster — inherits from cluster coordinator"
            );
            Ok(default_capability_bus(capability, coordinator))
        }
        Some(o) => build_bus_from_override(o).await,
    }
}

/// Build an `Arc<dyn KeyValueStore>` from a per-capability `store:`
/// override. Used by sessions / tasks / pipeline_store /
/// subscription_store boot paths when the operator sets an override.
///
/// Recognised forms:
/// - `kind: memory` / `kind: file` — built-in single-node primitives.
/// - `kind: <reverse-domain plugin id>` — registered Store plugin
///   (e.g. `dev.mcpg.kv.redis`). Wrapped in
///   [`StoreToKvAdapter`] keyed to the capability's `role`.
/// - `kind: <short alias>` — expanded to `dev.mcpg.kv.<alias>`
///   and looked up in the plugin registry.
///
/// `kind: cluster` is the meta-kind that delegates to the cluster
/// coordinator's primitive; it's handled by `resolve_capability_kv`
/// above and never reaches this builder.
pub(crate) async fn build_kv_from_override(
    over: &crate::config::StoreOverrideConfig,
    plugin_registry: &mcpg_plugin_host::PluginRegistry,
    role: mcpg_plugin_protocol::store::StoreRole,
) -> anyhow::Result<std::sync::Arc<dyn mcpg_cluster_api::KeyValueStore>> {
    use mcpg_cluster_api::KeyValueStore;
    use std::sync::Arc;
    over.validate()?;
    match over.kind.as_str() {
        "memory" => {
            let _ = over.as_memory()?;
            Ok(
                Arc::new(crate::builtins::cluster_primitives::MemoryKv::new())
                    as Arc<dyn KeyValueStore>,
            )
        }
        "file" => {
            let p = over.as_file()?;
            let kv = crate::builtins::cluster_primitives::FileKv::new(&p.dir)
                .await
                .map_err(|e| anyhow::anyhow!("file store override init: {e}"))?;
            Ok(kv as Arc<dyn KeyValueStore>)
        }
        // Plugin-id (reverse-domain) or short alias —
        // resolve_kind disambiguates. The resolved plugin must
        // be a registered Store with the requested role in its
        // `supported_roles()`. Wrap in StoreToKvAdapter so the
        // capability sees a role-less KeyValueStore.
        kind => {
            let plugin_id = if kind.contains('.') {
                kind.to_owned()
            } else {
                format!("dev.mcpg.kv.{kind}")
            };
            let store = plugin_registry.store_by_id(&plugin_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "store override kind '{kind}' resolved to plugin id \
                         '{plugin_id}' but no Store plugin with that id is \
                         registered. Either load the plugin via plugins[] or \
                         set kind to one of: cluster, memory, file."
                )
            })?;
            if !store.supported_roles().contains(&role) {
                anyhow::bail!(
                    "store override kind '{kind}' (plugin '{plugin_id}') does \
                     not support role '{role}'; supported roles: {:?}",
                    store.supported_roles()
                );
            }
            tracing::info!(
                kind,
                plugin_id = %plugin_id,
                role = %role,
                "store: kind resolved to plugin"
            );
            Ok(
                Arc::new(crate::app::plugin_kv_adapter::StoreToKvAdapter::new(
                    store, role,
                )) as Arc<dyn KeyValueStore>,
            )
        }
    }
}

/// Build an `Arc<dyn PubSub>` from a per-capability `bus:` override.
/// Used by delivery_bus / cancellation_bus boot paths when the
/// operator sets an override.
///
/// The recognised override kinds are in-process only (`memory`).
/// Operators wanting a redis / nats bus set
/// `cluster.kind: redis | nats` and capabilities inherit.
pub(crate) async fn build_bus_from_override(
    over: &crate::config::BusOverrideConfig,
) -> anyhow::Result<std::sync::Arc<dyn mcpg_cluster_api::PubSub>> {
    use mcpg_cluster_api::PubSub;
    use std::sync::Arc;
    over.validate()?;
    match over.kind.as_str() {
        "memory" => {
            let _ = over.as_memory()?;
            Ok(Arc::new(crate::builtins::cluster_primitives::MemoryBus::new()) as Arc<dyn PubSub>)
        }
        // `cluster` / `redis` / `nats` either rejected by `validate()`
        // above or routed through `resolve_capability_bus`; this arm
        // is unreachable when callers go through the resolver.
        other => anyhow::bail!(
            "bus override kind '{other}' not recognised. \
             Valid kinds: cluster, memory. (For redis or nats, set \
             `cluster.kind` instead.)"
        ),
    }
}

/// Wire the cluster_metering global audit
/// emitter to the freshly-built `Arc<PluginRegistry>` and spawn
/// the centralized `watch_peers` subscriber so peer-event audit
/// emission goes through ONE consumer (avoiding the fan-out
/// duplication that per-subscriber tapping would produce).
///
/// Idempotent across hot reloads: `set_audit_emitter` replaces
/// the global handle and any in-flight prior subscriber will
/// either continue (its Arc is still alive) or silently no-op
/// (Weak upgrade returns None) until the new subscriber arrives.
pub(crate) fn spawn_cluster_audit_taps(runtime: &GatewayRuntime) {
    let registry_arc = runtime.plugin_registry_arc();
    mcpg_plugin_host::cluster_metering::set_audit_emitter(Arc::downgrade(&registry_arc));

    let coordinator = match registry_arc.cluster_backend() {
        Some(c) => c,
        None => return,
    };
    let registry_for_task = registry_arc.clone();
    tokio::spawn(async move {
        use futures::StreamExt;
        let mut stream = coordinator.watch_peers().await;
        while let Some(event) = stream.next().await {
            let (kind, node_id, health) = match &event {
                mcpg_cluster_api::PeerEvent::Joined { peer } => {
                    ("joined", peer.node_id.clone(), None)
                }
                mcpg_cluster_api::PeerEvent::Left { node_id } => ("left", node_id.clone(), None),
                mcpg_cluster_api::PeerEvent::HealthChanged { node_id, health } => (
                    "health_changed",
                    node_id.clone(),
                    Some(format!("{:?}", health).to_ascii_lowercase()),
                ),
            };
            let audit_event = mcpg_plugin_host::audit_events::cluster_member_event(
                kind,
                &node_id,
                health.as_deref(),
                None,
            );
            let _ = registry_for_task.emit_audit_event(&audit_event).await;
        }
    });
}
