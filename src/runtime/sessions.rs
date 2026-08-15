use super::*;

impl GatewayRuntime {
    /// returns Err when adding a session for `principal_id` would
    /// breach the per-tenant cap; otherwise records the new session and
    /// returns Ok.
    pub(crate) fn try_acquire_tenant_session(
        &self,
        session_id: &str,
        principal_id: Option<&str>,
    ) -> Result<(), ()> {
        if self.max_sessions_per_tenant == 0 {
            return Ok(());
        }
        let tenant = principal_id.unwrap_or("anonymous").to_owned();
        let mut n = self
            .tenant_session_counts
            .entry(tenant.clone())
            .or_insert(0);
        if *n >= self.max_sessions_per_tenant {
            metrics::counter!(
                "mcpg_tenant_session_quota_rejected_total",
                "tenant" => tenant.clone(),
            )
            .increment(1);
            return Err(());
        }
        *n += 1;
        drop(n); // release shard before acquiring another
        self.session_tenants.insert(session_id.to_owned(), tenant);
        Ok(())
    }

    /// Decrement the tenant counter on session terminate.
    pub(crate) fn release_tenant_session(&self, session_id: &str) {
        if let Some((_, tenant)) = self.session_tenants.remove(session_id)
            && let Some(mut n) = self.tenant_session_counts.get_mut(&tenant)
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                drop(n);
                self.tenant_session_counts.remove(&tenant);
            }
        }
    }

    /// Per-session request-id uniqueness tracker.
    /// Returns `Err` when `id` has already been seen on this session.
    /// Backed by a HashSet for O(1) membership plus a VecDeque for
    /// FIFO eviction. An earlier 1024-entry window could wrap on very
    /// long sessions; the cap is now 64 KiB and on eviction we
    /// increment `mcpg_request_id_window_evicted_total` so operators
    /// see the risk surface (a wrapped window can let a stale id replay).
    const SEEN_ID_CAP_PER_SESSION: usize = 65_536;
    /// Upper bound on how many per-session windows are held at once.
    ///
    /// A window is keyed on the client-supplied session header and created
    /// before the session has been resolved, so a caller presenting a fresh
    /// fabricated session id on every request accumulates windows that no
    /// cleanup path can reclaim — with no session row,
    /// `cascade_session_cleanup` never fires for them. This is the same leak
    /// the `session_ephemeral` guard above already avoids for row-less
    /// sessions; the cap covers the ids that were never minted at all.
    const MAX_TRACKED_SESSION_WINDOWS: usize = 100_000;
    pub(crate) fn record_client_request_id(
        &self,
        session_id: Option<&str>,
        session_ephemeral: bool,
        id: &Value,
    ) -> Result<(), ()> {
        if self.relax_request_id_uniqueness {
            return Ok(()); // benchmark/load-test mode: fixed-id replay is allowed
        }
        // An ephemeral row-less session carries a fresh synthetic id per
        // request, so its JSON-RPC id-space cannot collide within the
        // "session" and recording it would leak a tracker entry that
        // terminate_session (which never runs for row-less sessions) can
        // never reclaim.
        if session_ephemeral {
            return Ok(());
        }
        let sid = match session_id {
            Some(s) => s.to_owned(),
            None => return Ok(()), // pre-session ids (initialize) are unique by construction
        };
        let id_str = match id {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            // null/bool/object/array are already rejected by validate_jsonrpc_id
            _ => return Ok(()),
        };
        // Refuse to open a NEW window once the map is full; sessions that
        // already have one keep deduplicating normally. Skipping is a
        // degradation of duplicate detection under flood, which is strictly
        // better than unbounded caller-controlled growth.
        if self.seen_request_ids.len() >= Self::MAX_TRACKED_SESSION_WINDOWS
            && !self.seen_request_ids.contains_key(&sid)
        {
            metrics::counter!("mcpg_request_id_window_capacity_skipped_total").increment(1);
            return Ok(());
        }
        let mut entry = self.seen_request_ids.entry(sid).or_default();
        if entry.insert(id_str, Self::SEEN_ID_CAP_PER_SESSION) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Drop a session's id tracker on terminate so a new session with
    /// the same id starts with a clean id-space.
    pub(crate) fn forget_session_request_ids(&self, session_id: &str) {
        self.seen_request_ids.remove(session_id);
    }

    /// Legacy (`2025-11-25`) session-wide `logging/setLevel` floor for
    /// `session_id`, used to gate pipeline `log` steps (LOG-2). Returns
    /// `None` on the modern wire (per-request gate instead), when there
    /// is no session, or when the session can't be loaded.
    pub(crate) fn legacy_session_log_level(
        &self,
        ctx: &RequestContext,
    ) -> Option<crate::protocol::LoggingLevel> {
        if ctx.negotiated_version == crate::protocol::version::ProtocolVersion::V_2026_07_28 {
            return None;
        }
        let session_id = ctx.session_id.as_deref()?;
        self.session_store
            .load_session(Some(session_id), false)
            .ok()
            .map(|snapshot| snapshot.log_level)
    }

    /// SEP-defined pagination contract: an opaque cursor that does not
    /// decode (malformed, forged MAC, or replayed across sessions) is
    /// an invalid-params error, NOT a silent restart at page 1.
    /// Returns `true` when `cursor` is absent or decodes against this
    /// request's session-bound key, `false` when it is present and
    /// undecodable.
    pub(crate) fn cursor_is_valid(&self, cursor: Option<&str>, session_id: Option<&str>) -> bool {
        match cursor {
            None => true,
            Some(c) => decode_cursor(c, Some(&self.cursor_binding_key(session_id))).is_some(),
        }
    }

    /// Modern stateless mode. When a modern (`V_2026_07_28`)
    /// request arrives without an `Mcp-Session-Id`, mint an
    /// ephemeral operational session bound only to this request so
    /// the legacy session-requiring code paths
    /// (`load_session_cached(require_operational=true)`,
    /// `subscribe_session_delivery`, etc.) still work without the
    /// client needing to do a legacy `initialize` handshake first.
    ///
    /// The synthetic session is created in `Operational` phase
    /// immediately and is naturally evicted by the session store's
    /// TTL. Pure stateless dispatch — fan-out + per-tenant
    /// bookkeeping with no per-request session row — is a deeper
    /// architectural change and a separate follow-up.
    ///
    /// Returns the (possibly updated) context. Pass-through when
    /// the session header is already present or when the version
    /// is legacy.
    pub(crate) fn ensure_modern_session(&self, ctx: &RequestContext) -> ModernSessionOutcome {
        if ctx.session_id.is_some() {
            return ModernSessionOutcome::Ready(ctx.clone());
        }
        if ctx.negotiated_version != crate::protocol::version::ProtocolVersion::V_2026_07_28 {
            return ModernSessionOutcome::Ready(ctx.clone());
        }

        // Deterministic, coordination-free continuity. When a shared
        // `sessions.synthetic_session_key` is configured (identical across
        // replicas), derive the synthetic session id from the principal via
        // HMAC so every replica computes the SAME id. The session row is
        // persisted to cluster KV, so `tasks/create` on replica A is
        // visible to `tasks/get` on B. HMAC (not a bare hash) keeps the id
        // unguessable, and the derivation input is the trust-qualified
        // principal key (trust tier + provider + issuer + subject), so a
        // header-asserted `alice` cannot re-derive a verified `alice`'s
        // session id. Restricted to Verified callers: cross-replica
        // continuity is a guarantee only cryptographic identity earns; a
        // header-asserted caller (only seen when the operator opted into
        // `server.trust_subject_header`) falls through to per-instance
        // continuity below.
        if ctx.identity.trust_level() == RequestTrustLevel::Verified
            && let Some(principal_key) = ctx.identity.synthetic_principal_key()
            && let Some(key) = self.synthetic_session_key()
        {
            let sid = Self::derive_synthetic_session_id(&key, &principal_key);
            // Already operational on this replica or another (KV read-back)?
            if self.session_store.load_session(Some(&sid), false).is_ok() {
                metrics::counter!("mcpg_modern_stateless_sessions_reused_total").increment(1);
                let mut new_ctx = ctx.clone();
                new_ctx.session_id = Some(sid);
                return ModernSessionOutcome::Ready(new_ctx);
            }
            let snap = self.session_store.create_session_with_id(
                &sid,
                crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION,
                &Self::modern_synthetic_init_params(),
            );
            // The store signals `sessions.max_sessions` rejection with an
            // empty-id snapshot; surface honest backpressure instead of
            // dispatching against a session that was never stored.
            if snap.session_id.is_empty() {
                return ModernSessionOutcome::CapacityExhausted;
            }
            self.session_store.bind_session_owner(
                &snap.session_id,
                ctx.identity.synthetic_principal_key().as_deref(),
            );
            if let Err(error) = self
                .session_store
                .transition_session_to_operational(&snap.session_id)
            {
                tracing::warn!(
                    error = ?error,
                    "modern stateless mode: failed to transition synthetic session to Operational"
                );
            } else {
                metrics::counter!("mcpg_modern_stateless_sessions_minted_total").increment(1);
            }
            let mut new_ctx = ctx.clone();
            new_ctx.session_id = Some(snap.session_id);
            return ModernSessionOutcome::Ready(new_ctx);
        }

        // No shared key — fall back to the per-instance alias map. When the
        // request carries an authenticated principal, reuse the per-principal
        // synthetic session so two requests from the same client on THIS
        // replica share a session id (task / subscription continuity within
        // one instance; cross-replica continuity needs the key above). The
        // alias is keyed on the trust-qualified principal key so a
        // header-asserted `alice` and a verified `alice` never share an
        // alias. Anonymous traffic still mints per-request — no stable key.
        if let Some(principal_key) = ctx.identity.synthetic_principal_key()
            && let Some(existing) = self.modern_session_aliases.get(&principal_key)
        {
            // Verify the alias still resolves in the session store
            // — TTL eviction can outlive the alias map entry. If
            // the store dropped the session, fall through to mint
            // a fresh one and refresh the alias.
            let candidate = existing.clone();
            drop(existing); // release the DashMap ref before re-entry below
            if self
                .session_store
                .load_session(Some(&candidate), false)
                .is_ok()
            {
                metrics::counter!("mcpg_modern_stateless_sessions_reused_total").increment(1);
                let mut new_ctx = ctx.clone();
                new_ctx.session_id = Some(candidate);
                return ModernSessionOutcome::Ready(new_ctx);
            }
            // Stale alias — drop it so the create-and-refresh
            // path below installs a fresh mapping.
            self.modern_session_aliases.remove(&principal_key);
        }

        // Authenticated principal without cross-replica key: mint a
        // stored session and stash the per-instance alias so subsequent
        // requests from the same principal reuse it (task / subscription
        // continuity within this replica).
        if let Some(principal_key) = ctx.identity.synthetic_principal_key() {
            let synthetic_params = Self::modern_synthetic_init_params();
            let snap = self.session_store.create_session(
                crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION,
                &synthetic_params,
            );
            if snap.session_id.is_empty() {
                return ModernSessionOutcome::CapacityExhausted;
            }
            self.session_store
                .bind_session_owner(&snap.session_id, ctx.identity.principal_id());
            // Best-effort transition to Operational so downstream
            // `load_session_cached(require_operational=true)` calls
            // succeed. A failure here means the store entry never
            // landed — the resulting dispatch will surface the legacy
            // SessionAccessError, which is preferable to silent
            // success.
            if let Err(error) = self
                .session_store
                .transition_session_to_operational(&snap.session_id)
            {
                tracing::warn!(
                    error = ?error,
                    "modern stateless mode: failed to transition synthetic session to Operational"
                );
            } else {
                metrics::counter!("mcpg_modern_stateless_sessions_minted_total").increment(1);
            }
            self.modern_session_aliases
                .insert(principal_key, snap.session_id.clone());
            let mut new_ctx = ctx.clone();
            new_ctx.session_id = Some(snap.session_id);
            return ModernSessionOutcome::Ready(new_ctx);
        }

        // Anonymous traffic: no principal key means no continuity is
        // possible (the next request cannot re-derive this id, the id is
        // never sent to the client, and the modern wire ignores inbound
        // `Mcp-Session-Id`), so the session is fully ephemeral — no store
        // row at all. Every session-keyed structure on the dispatch path
        // (deliveries, request-id dedup, cancellation) works on the id
        // string, and `load_session_cached` is pre-seeded with the
        // synthetic snapshot. Continuation points materialize the row on
        // demand (see [`Self::materialize_ephemeral_session`]).
        metrics::counter!("mcpg_modern_stateless_sessions_ephemeral_total").increment(1);
        ModernSessionOutcome::Ready(
            ctx.clone()
                .with_ephemeral_session(Self::ephemeral_session_snapshot()),
        )
    }

    /// Synthetic Operational snapshot backing an ephemeral (row-less)
    /// session — the same shape a stored synthetic session would have
    /// after `create_session` + `transition_session_to_operational`.
    pub(crate) fn ephemeral_session_snapshot() -> SessionSnapshot {
        Self::ephemeral_session_snapshot_for(
            crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION,
        )
    }

    /// [`Self::ephemeral_session_snapshot`] at a specific negotiated
    /// protocol revision (the legacy session-optional lane pins the
    /// request's own version so downstream version-aware code branches
    /// consistently).
    pub(crate) fn ephemeral_session_snapshot_for(protocol_version: &str) -> SessionSnapshot {
        let params = Self::modern_synthetic_init_params();
        SessionSnapshot {
            session_id: uuid::Uuid::new_v4().to_string(),
            protocol_version: protocol_version.to_owned(),
            client_info: params.client_info,
            client_capabilities: params.capabilities,
            phase: session_store::SessionPhase::Operational,
            log_level: crate::protocol::LoggingLevel::Info,
            created_at: Utc::now(),
            owner_principal: None,
        }
    }

    /// Create the real session-store row for an ephemeral session at the
    /// point a continuation outlives the request: a materialized task, an
    /// MRTR suspension awaiting resume, or a `subscriptions/listen`
    /// stream. Ephemeral sessions are minted only for anonymous callers,
    /// so the row has no owner to bind. Idempotent
    /// (`create_session_with_id` returns an existing row unchanged); a
    /// store that refuses the row (session cap) is logged and the
    /// continuation proceeds degraded — exactly the pre-existing behavior
    /// for a stored session evicted mid-flight.
    pub(crate) fn materialize_ephemeral_session(&self, session_id: &str) {
        let snap = self.session_store.create_session_with_id(
            session_id,
            crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION,
            &Self::modern_synthetic_init_params(),
        );
        if snap.session_id.is_empty() {
            tracing::warn!(
                session_id,
                "session capacity exhausted while materializing an ephemeral session; \
                 continuation proceeds without a stored row"
            );
            return;
        }
        if let Err(error) = self
            .session_store
            .transition_session_to_operational(session_id)
        {
            tracing::warn!(
                error = ?error,
                session_id,
                "failed to transition materialized ephemeral session to Operational"
            );
        } else {
            metrics::counter!("mcpg_modern_stateless_sessions_minted_total").increment(1);
        }
    }

    /// The synthetic `InitializeParams` minted for a modern stateless
    /// session (shared by the deterministic + per-instance paths).
    pub(crate) fn modern_synthetic_init_params() -> crate::protocol::InitializeParams {
        crate::protocol::InitializeParams {
            protocol_version: crate::protocol::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION
                .to_owned(),
            capabilities: Default::default(),
            client_info: crate::protocol::ImplementationInfo {
                name: "mcpg.stateless.synthetic".to_owned(),
                title: None,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                description: Some(
                    "ephemeral session minted for a modern stateless request".to_owned(),
                ),
                website_url: None,
                icons: None,
            },
        }
    }

    /// Resolve the operator-configured 32-byte synthetic-session key
    /// (`sessions.synthetic_session_key`, base64). `None` when unset,
    /// not yet wired (no `shared_services`), or malformed (wrong length /
    /// bad base64) — callers then fall back to per-instance ids. The
    /// boot-time wiring logs a WARN on a malformed key + on the
    /// clustered-without-key case, so a silent `None` here only
    /// happens on the intended per-instance default.
    pub(crate) fn synthetic_session_key(&self) -> Option<[u8; 32]> {
        use base64::Engine;
        let services = self.shared_services.load();
        let snapshot = &services.as_ref()?.config_snapshot;
        // 1. Explicit operator key wins. A malformed explicit key falls
        // through to derivation/None rather than silently using bad material;
        // the boot wiring already WARNs.
        if let Some(raw) = snapshot
            .mcp
            .configurations
            .sessions
            .synthetic_session_key
            .as_ref()
            && let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw.trim())
            && decoded.len() == 32
        {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            return Some(key);
        }
        // 2. Clustered fallback: derive a domain-separated sub-key from the
        // cluster-stable secret so deterministic per-principal synthetic
        // sessions (and thus cross-replica modern resume) work by default
        // whenever cluster state-encryption is configured — no separate
        // sessions.synthetic_session_key needed. The id stays principal-derived
        // (HMAC over the trust-qualified principal key), so a different
        // principal still derives a different session id and is rejected.
        let base = crate::app::cluster_state_key_bytes(&snapshot.cluster)
            .ok()
            .flatten()?;
        Some(crate::app::derive_cluster_subkey(
            &base,
            crate::app::SYNTHETIC_SESSION_KEY_DOMAIN,
        ))
    }

    /// Derive the deterministic synthetic session id for a principal:
    /// `mcpg-m-<hex(HMAC-SHA256(key, "mcpg:modern-session:" || principal_key))>`.
    /// `principal_key` is the trust-qualified key from
    /// [`RequestIdentity::synthetic_principal_key`] (trust tier + provider +
    /// issuer + subject), so the derivation binds to *how* the caller was
    /// authenticated — a header-asserted `alice` cannot re-derive a verified
    /// `alice`'s id. HMAC (not a bare hash) so the id is not computable by a
    /// client that knows another principal's id; the domain-separation prefix
    /// keeps the id space disjoint from any other HMAC use of the same key.
    pub(crate) fn derive_synthetic_session_id(key: &[u8; 32], principal_key: &str) -> String {
        use std::fmt::Write;
        let mut msg = Vec::with_capacity(20 + principal_key.len());
        msg.extend_from_slice(b"mcpg:modern-session:");
        msg.extend_from_slice(principal_key.as_bytes());
        let mac = hmac_sha256::HMAC::mac(&msg, key);
        let mut id = String::with_capacity(7 + 64);
        id.push_str("mcpg-m-");
        for byte in mac {
            let _ = write!(id, "{byte:02x}");
        }
        id
    }

    /// Terminate a session and cascade cleanup across all subsystems:
    /// 1. Remove from session store  2. Release tenant quota  3. Purge progress state
    /// 4. Clear completion rate-limiter bucket  5. Drop resource subscriptions
    /// 6. Forget request-id uniqueness tracker  7. Cancel non-terminal tasks
    /// 8. Record session duration metric.
    pub fn terminate_session(&self, session_id: &str) -> bool {
        // Load session before termination to record duration
        let session_snapshot = self
            .session_store
            .load_session(Some(session_id), false)
            .ok();
        let removed = self.session_store.terminate_session(session_id);
        if removed {
            self.cascade_session_cleanup(session_id, session_snapshot, "terminated");
        }
        removed
    }

    /// Runtime-side per-session cleanup for a session whose store row has
    /// ALREADY been removed — by explicit [`Self::terminate_session`] or by
    /// idle eviction (via [`Self::on_session_evicted`]). Releases tenant
    /// quota, prunes progress / completion-limiter / subscription / request-id
    /// state, cancels non-terminal tasks, and records the duration metric +
    /// audit. `reason` distinguishes the caller ("terminated" / "idle_expired").
    pub(crate) fn cascade_session_cleanup(
        &self,
        session_id: &str,
        session_snapshot: Option<SessionSnapshot>,
        reason: &str,
    ) {
        // decrement the tenant counter.
        self.release_tenant_session(session_id);
        // prune progress monotonicity state for this session.
        self.execution_dispatcher
            .clear_progress_state_for_session(session_id);
        // prune the completion rate-limit token bucket keyed by session_id.
        self.completion_limiter.remove(session_id);
        // Clean up subscriptions for this session. Through the service, not
        // the store: dropping the rows alone leaves the watch engine still
        // counting this session as a subscriber, so its watcher keeps polling
        // a resource nobody is listening to for the life of the process.
        self.subscriptions().release_session(session_id);
        // drop the request-id uniqueness tracker so a new session reusing the
        // id starts with a clean id-space.
        self.forget_session_request_ids(session_id);

        // non-terminal tasks owned by the session would otherwise linger until
        // their TTL; the session ending is a valid terminal signal. `cancel_task`
        // is a no-op on already-terminal tasks.
        if let Ok((tasks, _)) = self.task_store.list_tasks(session_id, None, usize::MAX) {
            for task in tasks {
                if matches!(
                    task.status,
                    crate::protocol::TaskStatus::Working
                        | crate::protocol::TaskStatus::InputRequired
                ) && let Ok(record) = self.task_store.cancel_task(&task.task_id, session_id)
                {
                    metrics::counter!("mcpg_tasks_cancelled_on_session_termination_total")
                        .increment(1);
                    // Broadcast onto the cluster bus so a peer running the
                    // task's background work can interrupt it too.
                    let bus = self.cancellation_bus.clone();
                    let event = cancellation_bus::CancellationEvent {
                        target_id: record.task.task_id.clone(),
                        kind: cancellation_bus::CancellationKind::Task,
                        session_id: session_id.to_owned(),
                        // Session teardown has no active caller to attribute.
                        principal_id: None,
                        reason: Some(format!("session {reason}")),
                    };
                    tokio::spawn(async move {
                        if let Err(e) = bus.publish(event).await {
                            tracing::warn!(
                                error = %e,
                                "failed to broadcast task cancellation on session teardown"
                            );
                        }
                    });
                }
            }
        }

        metrics::gauge!("mcpg_active_sessions").decrement(1.0);
        if let Some(snapshot) = session_snapshot {
            let duration = (Utc::now() - snapshot.created_at).num_seconds().max(0) as f64;
            metrics::histogram!("mcpg_session_duration_seconds").record(duration);
            info!(
                session_id = %session_id,
                duration_secs = duration,
                reason = %reason,
                "session ended"
            );
            // Audit: fire-and-forget through the async audit fan-out. Auditors
            // join opened ↔ ended by `details.session_id`.
            let registry = Arc::clone(&self.plugin_registry);
            let session_id_owned = session_id.to_owned();
            let client_name = snapshot.client_info.name.clone();
            let reason_owned = reason.to_owned();
            tokio::spawn(async move {
                let event = mcpg_plugin_host::audit_events::session_terminated_event(
                    &session_id_owned,
                    duration,
                    &reason_owned,
                    Some(&client_name),
                );
                let _ = registry.emit_audit_event(&event).await;
            });
        }
    }

    /// Cascade cleanup for a session the store dropped due to idle expiry
    /// (delivered on the eviction channel installed by
    /// [`Self::install_session_eviction_notifier`]). Guards the narrow reuse
    /// window: if a live session now holds this id (a client re-created it, or
    /// a deterministic-modern id was re-derived), its id-keyed state is
    /// legitimate and must not be wiped.
    pub(crate) fn on_session_evicted(&self, session_id: &str) {
        if self.session_store.contains_active_session(session_id) {
            return;
        }
        metrics::counter!("mcpg_sessions_idle_expired_total").increment(1);
        self.cascade_session_cleanup(session_id, None, "idle_expired");
    }

    /// Register the store→runtime idle-eviction cascade channel's sender on the
    /// session store (called once at boot). The store forwards every
    /// idle-evicted session id, which the drain task feeds to
    /// [`Self::on_session_evicted`].
    pub(crate) fn install_session_eviction_notifier(
        &self,
        notifier: tokio::sync::mpsc::UnboundedSender<String>,
    ) {
        self.session_store.set_eviction_notifier(notifier);
    }

    pub fn session_protocol_version(&self, session_id: &str) -> Option<String> {
        self.session_store.session_protocol_version(session_id)
    }
}
