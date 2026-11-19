use super::*;

/// What [`GatewayRuntime::ensure_session`] gives the dispatch: the context
/// bound to its session, or the answer that no session row can be created
/// now (`sessions.max_sessions`, or the caller's `max_sessions_per_tenant`),
/// which the transport turns into backpressure.
pub(crate) enum SessionOutcome {
    Ready(RequestContext),
    CapacityExhausted,
}

/// A locally-registered cancellation token plus the identity that owns
/// the in-flight request/task it can interrupt. The cancellation-bus
/// subscriber checks an incoming event's principal/session against these
/// before firing the token, so one principal cannot abort another's
/// in-flight work by guessing its request/task id.
#[derive(Clone)]
pub(crate) struct RegisteredCancellation {
    pub(super) token: tokio_util::sync::CancellationToken,
    /// Session that owns the in-flight work. `None` when the owner had
    /// no session.
    pub(super) owner_session: Option<String>,
    /// Principal (OIDC `sub` claim or equivalent) that owns the work.
    /// `None` for an unauthenticated owner.
    pub(super) owner_principal: Option<String>,
}

/// Decide whether a resuming caller owns a suspended pipeline. Ownership
/// requires the same principal; for an identified owner the session must
/// also match. An anonymous owner (`None` principal) is matched by
/// principal alone — its session is per-request ephemeral, so replay of
/// anonymous resumes is covered by the requestState single-use guard
/// rather than a session comparison. Missing/empty sessions never satisfy
/// the identified-owner case.
pub(super) fn resumer_owns_pipeline(
    owner_principal: Option<&str>,
    owner_session: &str,
    resumer_principal: Option<&str>,
    resumer_session: Option<&str>,
) -> bool {
    let principal_match = owner_principal == resumer_principal;
    let session_match = owner_principal.is_none()
        || (!owner_session.is_empty() && resumer_session == Some(owner_session));
    principal_match && session_match
}

/// Decide whether a caller may operate on a session. The caller's
/// trust-qualified principal key (see `synthetic_principal_key` — embeds
/// trust tier + provider + issuer, so a header-asserted `alice` can't
/// match a verified `alice`) must equal the session creator's. An
/// anonymous-owned session (`None`) is matched only by an anonymous
/// caller, and an identified caller cannot claim an anonymous session
/// (or vice versa).
pub(super) fn session_owner_matches(owner_key: Option<&str>, caller_key: Option<&str>) -> bool {
    owner_key == caller_key
}

/// Decide whether a cancellation event's requester owns the in-flight
/// work the token interrupts. Mirrors [`resumer_owns_pipeline`]: the
/// requester must be the same principal; an identified owner must also
/// share the session. Anonymous owners are matched by principal alone.
pub(super) fn cancellation_requester_is_owner(
    registered: &RegisteredCancellation,
    event: &cancellation_bus::CancellationEvent,
) -> bool {
    let principal_match = registered.owner_principal.as_deref() == event.principal_id.as_deref();
    let session_match = registered.owner_principal.is_none()
        || registered
            .owner_session
            .as_deref()
            .is_some_and(|owner| owner == event.session_id);
    principal_match && session_match
}

/// `ctx` bound to the session `session_id`.
fn bound_to(mut ctx: RequestContext, session_id: String) -> RequestContext {
    ctx.session_id = Some(session_id);
    ctx
}

impl GatewayRuntime {
    /// Count `session_id` toward the sessions of `owner`, its
    /// trust-qualified principal key (`None` counts toward `anonymous`).
    /// `Err` when the owner already holds `max_sessions_per_tenant`
    /// sessions. With `fleet_count`, the count is the fleet's when the
    /// session store keeps one every replica shares; otherwise, and for a
    /// row only this replica uses, it is this replica's. A session already
    /// counted counts once.
    pub(crate) fn try_acquire_tenant_session(
        &self,
        session_id: &str,
        owner: Option<&str>,
        fleet_count: bool,
    ) -> Result<(), ()> {
        if self.max_sessions_per_tenant == 0 {
            return Ok(());
        }
        let tenant = owner.unwrap_or("anonymous");
        let refused = || -> Result<(), ()> {
            metrics::counter!(
                "mcpg_tenant_session_quota_rejected_total",
                "tenant" => tenant.to_owned(),
            )
            .increment(1);
            Err(())
        };
        if fleet_count {
            match self
                .session_store
                .claim_tenant_slot(session_id, self.max_sessions_per_tenant)
            {
                Some(true) => return Ok(()),
                Some(false) => return refused(),
                None => {}
            }
        }
        use dashmap::mapref::entry::Entry;
        // Lock order: the session's entry, then the tenant's count; the
        // release takes them one at a time.
        let Entry::Vacant(counted) = self.session_tenants.entry(session_id.to_owned()) else {
            return Ok(());
        };
        let mut held = self
            .tenant_session_counts
            .entry(tenant.to_owned())
            .or_insert(0);
        if *held >= self.max_sessions_per_tenant {
            drop(held);
            return refused();
        }
        *held += 1;
        drop(held);
        counted.insert(tenant.to_owned());
        Ok(())
    }

    /// Give back the count [`Self::try_acquire_tenant_session`] took for
    /// `session_id` on this replica.
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

    /// SEP-defined pagination contract: an opaque cursor that does not
    /// decode (malformed, forged MAC, or replayed across sessions) is
    /// an invalid-params error, NOT a silent restart at page 1.
    /// Returns `true` when `cursor` is absent or decodes against this
    /// request's session-bound key, `false` when it is present and
    /// undecodable.
    pub(crate) fn cursor_is_valid(
        &self,
        cursor: Option<&str>,
        request_context: &RequestContext,
    ) -> bool {
        match cursor {
            None => true,
            Some(c) => decode_cursor(c, Some(&self.cursor_binding_key(request_context))).is_some(),
        }
    }

    /// Bind a request to the session its continuations (tasks, MRTR
    /// resumes, `subscriptions/listen`, deliveries) live under. No client
    /// names a session: the runtime derives or mints it from the caller.
    ///
    /// - A context that already carries a session id keeps it; only the
    ///   stdio transport sets one, its process session. The read keeps the
    ///   row alive, and a row the idle reaper took is created again under
    ///   the same id.
    /// - A verified caller, when a synthetic-session key is configured,
    ///   gets the row whose id every replica derives from its principal
    ///   key (and the client the request names), so its tasks and listen
    ///   streams are found on any replica.
    /// - Any other identified caller gets one row per principal on this
    ///   replica.
    /// - An anonymous caller has no stable key, so its session is
    ///   ephemeral: an id for this request with no row; a continuation
    ///   creates the row ([`Self::materialize_ephemeral_session`]).
    ///
    /// Every row is owned by the caller's trust-qualified principal key
    /// and counts toward its `max_sessions_per_tenant`: a derived row and
    /// an anonymous row across the fleet, a per-replica row on its replica.
    pub(crate) fn ensure_session(&self, ctx: RequestContext) -> SessionOutcome {
        if let Some(session_id) = ctx.session_id.as_deref() {
            if self.session_store.load_session(session_id).is_none()
                && !self.materialize_ephemeral_session(session_id)
            {
                return SessionOutcome::CapacityExhausted;
            }
            return SessionOutcome::Ready(ctx);
        }
        let Some(principal_key) = ctx.identity.synthetic_principal_key() else {
            metrics::counter!("mcpg_sessions_ephemeral_total").increment(1);
            return SessionOutcome::Ready(
                ctx.with_ephemeral_session(Self::ephemeral_session_snapshot()),
            );
        };

        // Derived across replicas: HMAC over the trust-qualified principal
        // key, so a header-asserted `alice` cannot re-derive a verified
        // `alice`'s id and no client can compute another principal's.
        // Only a verified caller earns continuity across replicas. The
        // client the request names joins the input, so two hosts on one
        // credential hold two sessions; a request naming no client keeps
        // the principal's own session.
        if ctx.identity.trust_level() == RequestTrustLevel::Verified
            && let Some(sid) = self.derived_session_id(
                &principal_key,
                ctx.client.as_ref().map(|client| client.name.as_str()),
            )
        {
            if self.session_store.load_session(&sid).is_some() {
                metrics::counter!("mcpg_sessions_reused_total").increment(1);
                return SessionOutcome::Ready(bound_to(ctx, sid));
            }
            let created = self.session_store.create_session_with_id(&sid);
            if !self.admit_session(&created, Some(principal_key.as_str()), true) {
                return SessionOutcome::CapacityExhausted;
            }
            return SessionOutcome::Ready(bound_to(ctx, created.session_id));
        }

        // One row per principal on this replica. The alias is keyed on the
        // trust-qualified principal key, so a header-asserted `alice` and a
        // verified `alice` never share one.
        if let Some(existing) = self.session_aliases.get(&principal_key) {
            let candidate = existing.clone();
            drop(existing); // release the DashMap ref before re-entry below
            // TTL eviction can outlive the alias entry: a stale alias is
            // replaced by a fresh row.
            if self.session_store.load_session(&candidate).is_some() {
                metrics::counter!("mcpg_sessions_reused_total").increment(1);
                return SessionOutcome::Ready(bound_to(ctx, candidate));
            }
            self.session_aliases.remove(&principal_key);
        }
        // Every replica that serves the principal holds such a row, so the
        // row counts on this replica only: a fleet count would refuse the
        // principal on every replica but the first.
        let created = self.session_store.create_session();
        if !self.admit_session(&created, Some(principal_key.as_str()), false) {
            return SessionOutcome::CapacityExhausted;
        }
        self.session_aliases
            .insert(principal_key, created.session_id.clone());
        SessionOutcome::Ready(bound_to(ctx, created.session_id))
    }

    /// Bind the row a create returned to `owner` and count it toward the
    /// owner's `max_sessions_per_tenant` (across the fleet with
    /// `fleet_count`). `false` when the store refused the row (an empty
    /// id), when another principal owns it, or when the owner is at its
    /// cap; a row over the cap is removed again.
    fn admit_session(
        &self,
        created: &SessionSnapshot,
        owner: Option<&str>,
        fleet_count: bool,
    ) -> bool {
        let session_id = created.session_id.as_str();
        if session_id.is_empty() {
            return false;
        }
        // An owner is bound once and never replaced. The slot of a fleet
        // count is keyed by the row's owner, so it is bound before the claim.
        match created.owner_principal.as_deref() {
            Some(bound) if Some(bound) != owner => return false,
            None if owner.is_some() => self.session_store.bind_session_owner(session_id, owner),
            _ => {}
        }
        if self
            .try_acquire_tenant_session(session_id, owner, fleet_count)
            .is_err()
        {
            self.session_store.terminate_session(session_id);
            return false;
        }
        metrics::counter!("mcpg_sessions_minted_total").increment(1);
        true
    }

    /// The snapshot an ephemeral (row-less) session runs under.
    pub(crate) fn ephemeral_session_snapshot() -> SessionSnapshot {
        SessionSnapshot {
            session_id: uuid::Uuid::new_v4().to_string(),
            created_at: Utc::now(),
            owner_principal: None,
        }
    }

    /// Create the row of an ephemeral session at the point a continuation
    /// outlives the request: a materialized task, an MRTR suspension
    /// awaiting resume, or a `subscriptions/listen` stream; and the stdio
    /// transport's process session. Ephemeral sessions are minted only for
    /// anonymous callers, so the row has no owner and counts toward the
    /// `anonymous` cap. Idempotent (`create_session_with_id` returns an
    /// existing row unchanged). `false` when the store or the cap refuses
    /// the row; the caller then answers with backpressure or goes on
    /// without a stored row.
    pub(crate) fn materialize_ephemeral_session(&self, session_id: &str) -> bool {
        let created = self.session_store.create_session_with_id(session_id);
        if self.admit_session(&created, None, true) {
            return true;
        }
        tracing::warn!(
            session_id,
            "an ephemeral session got no row: the session store or the session cap refused it"
        );
        false
    }

    /// The synthetic-session id of a verified `principal_key` and the client
    /// the request names, under the key the shared services hold. `None`
    /// when no key is configured or the services are not yet wired.
    fn derived_session_id(&self, principal_key: &str, client: Option<&str>) -> Option<String> {
        let services = self.shared_services.load();
        let keyed = services.as_ref()?.synthetic_session_mac.as_deref()?;
        Some(Self::synthetic_session_id(keyed, principal_key, client))
    }

    /// Resolve the operator-configured 32-byte synthetic-session key
    /// (`sessions.synthetic_session_key`, base64) of `snapshot`. `None` when
    /// unset or malformed (wrong length / bad base64) — callers then fall
    /// back to per-instance ids. The boot-time wiring logs a WARN on a
    /// malformed key + on the clustered-without-key case, so a silent `None`
    /// here only happens on the intended per-instance default.
    pub(crate) fn synthetic_session_key(snapshot: &crate::config::AppConfig) -> Option<[u8; 32]> {
        use base64::Engine;
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
        // cluster-stable secret so derived per-principal sessions (and thus
        // cross-replica resume) work by default whenever cluster
        // state-encryption is configured — no separate
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

    /// The synthetic session id of `principal_key` under `key`, for a
    /// request that names no client.
    #[cfg(test)]
    pub(crate) fn derive_synthetic_session_id(key: &[u8; 32], principal_key: &str) -> String {
        Self::synthetic_session_id(&Self::synthetic_session_mac(key), principal_key, None)
    }

    /// The HMAC state keyed with `key` that has taken in the domain prefix,
    /// built once so each derivation only adds the principal.
    pub(crate) fn synthetic_session_mac(key: &[u8; 32]) -> hmac_sha256::HMAC {
        let mut mac = hmac_sha256::HMAC::new(key);
        mac.update(b"mcpg:modern-session:");
        mac
    }

    /// Derive the deterministic synthetic session id for a principal from
    /// the state [`Self::synthetic_session_mac`] keyed:
    /// `mcpg-m-<hex(HMAC-SHA256(key, "mcpg:modern-session:" || principal_key))>`,
    /// with `"\u{1f}client:" || name` after `principal_key` when the request
    /// names a client. `principal_key` is the trust-qualified key from
    /// [`RequestIdentity::synthetic_principal_key`] (trust tier + provider +
    /// issuer + subject), so the derivation binds to *how* the caller was
    /// authenticated — a header-asserted `alice` cannot re-derive a verified
    /// `alice`'s id. HMAC (not a bare hash) so the id is not computable by a
    /// client that knows another principal's id; the domain-separation prefix
    /// keeps the id space disjoint from any other HMAC use of the same key.
    pub(crate) fn synthetic_session_id(
        keyed: &hmac_sha256::HMAC,
        principal_key: &str,
        client: Option<&str>,
    ) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut mac = keyed.clone();
        mac.update(principal_key);
        if let Some(client) = client {
            mac.update("\u{1f}client:");
            mac.update(client);
        }
        let mut id = String::with_capacity(7 + 64);
        id.push_str("mcpg-m-");
        for byte in mac.finalize() {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        id
    }

    /// True when `request_context` may operate on `session_id`. With
    /// owner-binding disabled this is always true (possession-only).
    /// Otherwise the caller's trust-qualified principal key must match the
    /// session creator's (an anonymous-owned session is matched only by an
    /// anonymous caller); an unknown/expired session is treated as
    /// not-owned so a caller cannot probe its existence.
    pub(crate) fn caller_owns_session(
        &self,
        session_id: &str,
        request_context: &RequestContext,
    ) -> bool {
        if !self.bind_session_owner {
            return true;
        }
        let Some(snapshot) = self.session_store.load_session(session_id) else {
            return false;
        };
        let owner = snapshot.owner_principal;
        let caller = request_context.identity.synthetic_principal_key();
        if session_owner_matches(owner.as_deref(), caller.as_deref()) {
            return true;
        }
        metrics::counter!("mcpg_session_owner_mismatch_total").increment(1);
        tracing::warn!(
            session_id = %session_id,
            "session operation denied: caller principal does not own the session"
        );
        false
    }

    /// Terminate a session and clean up after it here, and — when this
    /// replica records the end — everywhere: see
    /// [`Self::finish_ended_session`].
    pub fn terminate_session(&self, session_id: &str) -> bool {
        let Some(ended) = self.session_store.terminate_session(session_id) else {
            return false;
        };
        self.finish_ended_session(&ended);
        true
    }

    /// The cleanup after a session ended, whose store copy and rows are
    /// already gone. Every replica drops what it keeps for the session
    /// itself: its tenant count, progress state, buffered notifications,
    /// and its holds on the session's subscriptions. The replica that
    /// recorded the end also does what the replicas share, once: it removes
    /// the session's subscriptions, cancels its non-terminal tasks, records
    /// the duration metric and the audit event, and tells the other
    /// replicas.
    pub(crate) fn finish_ended_session(&self, ended: &EndedSession) {
        let session_id = ended.session_id.as_str();
        self.release_tenant_session(session_id);
        self.execution_dispatcher
            .clear_progress_state_for_session(session_id);
        self.discard_pending_deliveries(session_id);
        // Through the service, not the store: dropping the rows alone leaves
        // the watch engine still counting this session as a subscriber, so its
        // watcher keeps polling a resource nobody is listening to for the life
        // of the process.
        if !ended.recorded {
            self.subscriptions().release_session_here(session_id);
            return;
        }
        self.subscriptions().release_session(session_id);

        // non-terminal tasks owned by the session would otherwise linger until
        // their TTL; the session ending is a valid terminal signal. `cancel_task`
        // is a no-op on already-terminal tasks.
        let reason = ended.reason.as_str();
        if let Ok(tasks) = self.task_store.list_tasks(session_id) {
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

        if ended.reason == session_store::SessionEndReason::IdleExpired {
            metrics::counter!("mcpg_sessions_idle_expired_total").increment(1);
        }
        let Some(snapshot) = ended.snapshot.as_ref() else {
            return;
        };
        self.session_fleet
            .tell_ended(session_id, snapshot.created_at, ended.reason);
        let duration = (Utc::now() - snapshot.created_at).num_seconds().max(0) as f64;
        metrics::histogram!("mcpg_session_duration_seconds").record(duration);
        info!(
            session_id = %session_id,
            duration_secs = duration,
            reason = %reason,
            "session ended"
        );
        // Audit: fire-and-forget through the async audit fan-out.
        let registry = Arc::clone(&self.plugin_registry);
        let session_id_owned = session_id.to_owned();
        let reason_owned = reason.to_owned();
        tokio::spawn(async move {
            let event = mcpg_plugin_host::audit_events::session_terminated_event(
                &session_id_owned,
                duration,
                &reason_owned,
                None,
            );
            let _ = registry.emit_audit_event(&event).await;
        });
    }

    /// Clean up after a session that ended without a call to
    /// [`Self::terminate_session`] (delivered on the channel installed by
    /// [`Self::install_session_end_notifier`], or told by another replica).
    /// Guards the narrow reuse window: if a live session now holds this id
    /// (the runtime minted it again, as a derived id comes back for the
    /// same principal), its id-keyed state is legitimate and must not be
    /// wiped.
    pub(crate) fn on_session_end(&self, ended: &EndedSession) {
        if self
            .session_store
            .contains_active_session(&ended.session_id)
        {
            return;
        }
        self.finish_ended_session(ended);
    }

    /// Another replica recorded the end of a session: drop this replica's
    /// copy, end the session's streams here, and clean up after it.
    pub(crate) fn on_session_ended_elsewhere(&self, event: &session_fleet::SessionEndedEvent) {
        let snapshot = self
            .session_store
            .drop_ended_session(&event.session_id, event.created_at);
        metrics::counter!(
            "mcpg_sessions_ended_elsewhere_total",
            "held" => if snapshot.is_some() { "true" } else { "false" },
        )
        .increment(1);
        self.on_session_end(&EndedSession {
            session_id: event.session_id.clone(),
            reason: event.reason,
            recorded: false,
            snapshot,
        });
    }

    /// Register the channel on which the session store tells of the sessions
    /// that end without a call to [`Self::terminate_session`] (called once at
    /// boot); the drain task feeds each to [`Self::on_session_end`].
    pub(crate) fn install_session_end_notifier(
        &self,
        notifier: tokio::sync::mpsc::UnboundedSender<EndedSession>,
    ) {
        self.session_store.set_end_notifier(notifier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::session_store::active_sessions_probe::ActiveSessions;

    fn runtime(max_sessions_per_tenant: usize) -> GatewayRuntime {
        let mut runtime = GatewayRuntime::new(
            "mcpg",
            "0.1.0",
            "127.0.0.1:8787",
            "/health",
            "/mcp",
            "info",
            vec![crate::config::SinkConfig {
                kind: "stdout".to_owned(),
                config: serde_json::json!({"format": "json"}),
                level: None,
            }],
            true,
        );
        runtime.set_max_sessions_per_tenant(max_sessions_per_tenant);
        runtime.set_bind_session_owner(true);
        runtime
    }

    fn verified(subject: &str) -> RequestIdentity {
        RequestIdentity::Verified {
            subject_id: subject.to_owned(),
            issuer: "https://idp.example".to_owned(),
            auth_provider: "oidc".to_owned(),
            source: "test".to_owned(),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes: std::collections::BTreeMap::new(),
        }
    }

    fn anonymous() -> RequestIdentity {
        RequestIdentity::Anonymous {
            source: "test".to_owned(),
        }
    }

    fn context(identity: RequestIdentity) -> RequestContext {
        RequestContext::new(GatewayRequestId::new(), None, identity, TransportKind::Http)
    }

    fn session_of(outcome: SessionOutcome) -> String {
        match outcome {
            SessionOutcome::Ready(ctx) => ctx.session_id.expect("a session is bound"),
            SessionOutcome::CapacityExhausted => panic!("the session cap refused the caller"),
        }
    }

    #[test]
    fn the_session_cap_counts_rows_per_principal() {
        let runtime = runtime(1);
        let alice = context(verified("alice"));
        let first = session_of(runtime.ensure_session(alice.clone()));
        assert_eq!(
            session_of(runtime.ensure_session(alice.clone())),
            first,
            "the principal's row is reused, not counted again"
        );

        // A second row for alice: the alias is gone, the first row lives on.
        runtime.session_aliases.clear();
        assert!(
            matches!(
                runtime.ensure_session(alice.clone()),
                SessionOutcome::CapacityExhausted
            ),
            "alice is at her cap of one row"
        );
        assert_eq!(
            runtime.session_store.active_session_count(),
            1,
            "the refused row is removed again"
        );

        let bob = context(verified("bob"));
        session_of(runtime.ensure_session(bob));

        assert!(runtime.materialize_ephemeral_session("anon-1"));
        assert!(
            runtime.materialize_ephemeral_session("anon-1"),
            "materializing a row twice counts it once"
        );
        assert!(
            !runtime.materialize_ephemeral_session("anon-2"),
            "anonymous rows count toward one cap"
        );
        assert_eq!(runtime.session_store.active_session_count(), 3);

        assert!(runtime.session_store.terminate_session(&first).is_some());
        runtime.release_tenant_session(&first);
        session_of(runtime.ensure_session(alice.clone()));
    }

    #[test]
    fn without_a_cap_every_principal_mints_freely() {
        let runtime = runtime(0);
        let alice = context(verified("alice"));
        for _ in 0..3 {
            runtime.session_aliases.clear();
            session_of(runtime.ensure_session(alice.clone()));
        }
        assert_eq!(runtime.session_store.active_session_count(), 3);
    }

    /// Without a synthetic-session key the row is still owned by the
    /// caller's trust-qualified principal key, the key the owner check
    /// compares: the owner passes it and a foreign principal does not.
    #[test]
    fn the_owner_is_the_principal_key_without_a_synthetic_key() {
        let runtime = runtime(0);
        let alice = context(verified("alice"));
        let sid = session_of(runtime.ensure_session(alice.clone()));
        assert_eq!(
            runtime
                .session_store
                .load_session(&sid)
                .unwrap()
                .owner_principal,
            alice.identity.synthetic_principal_key()
        );
        assert!(runtime.caller_owns_session(&sid, &alice));
        assert!(!runtime.caller_owns_session(&sid, &context(verified("bob"))));
        assert!(!runtime.caller_owns_session(&sid, &context(anonymous())));
        let header_alice = context(RequestIdentity::HttpHeader {
            subject_id: "alice".to_owned(),
            source: "test".to_owned(),
        });
        assert!(
            !runtime.caller_owns_session(&sid, &header_alice),
            "a header-asserted alice is not the verified alice"
        );
        assert!(
            !runtime.materialize_ephemeral_session(&sid),
            "an owned row is never rebound to an anonymous owner"
        );
        assert!(runtime.caller_owns_session(&sid, &alice));

        assert!(runtime.materialize_ephemeral_session("anon-1"));
        assert!(runtime.caller_owns_session("anon-1", &context(anonymous())));
        assert!(!runtime.caller_owns_session("anon-1", &alice));
        assert!(
            !runtime.caller_owns_session("never-minted", &alice),
            "an unknown session is not owned"
        );
    }

    #[tokio::test]
    async fn a_context_that_names_its_session_keeps_it() {
        let runtime = runtime(1);
        let mut stdio = context(anonymous());
        stdio.session_id = Some("process-session".to_owned());
        assert!(runtime.materialize_ephemeral_session("process-session"));
        assert_eq!(
            session_of(runtime.ensure_session(stdio.clone())),
            "process-session"
        );
        assert_eq!(runtime.session_store.active_session_count(), 1);

        // The idle reaper took the row: the next request creates it again.
        assert!(runtime.terminate_session("process-session"));
        assert_eq!(
            session_of(runtime.ensure_session(stdio.clone())),
            "process-session"
        );
        assert_eq!(runtime.session_store.active_session_count(), 1);
        assert!(runtime.caller_owns_session("process-session", &stdio));
    }

    #[test]
    fn an_anonymous_caller_runs_without_a_row() {
        let runtime = runtime(1);
        let first = session_of(runtime.ensure_session(context(anonymous())));
        let second = session_of(runtime.ensure_session(context(anonymous())));
        assert_ne!(first, second, "every anonymous request is its own session");
        assert_eq!(runtime.session_store.active_session_count(), 0);
    }

    /// `mcpg_active_sessions` comes back to where it started once every row
    /// the runtime minted has ended, refused rows included.
    #[tokio::test]
    async fn the_active_sessions_gauge_balances_across_mint_and_end() {
        let runtime = runtime(1);
        let probe = ActiveSessions::default();
        probe.watch(|| {
            let alice = context(verified("alice"));
            let row = session_of(runtime.ensure_session(alice.clone()));
            session_of(runtime.ensure_session(alice.clone()));
            runtime.session_aliases.clear();
            assert!(matches!(
                runtime.ensure_session(alice.clone()),
                SessionOutcome::CapacityExhausted
            ));
            assert!(runtime.materialize_ephemeral_session("anon-1"));
            assert_eq!(probe.net(), 2, "alice's row and the anonymous row");

            assert!(runtime.terminate_session(&row));
            assert!(runtime.terminate_session("anon-1"));
            assert!(!runtime.terminate_session("anon-1"));
            assert_eq!(probe.net(), 0);
        });
    }
}
