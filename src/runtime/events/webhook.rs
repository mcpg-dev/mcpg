//! `events/subscribe` and `events/unsubscribe` for webhook delivery.
//!
//! Subscribe runs the cheap local checks first (callback URL policy, the
//! caller's trust, the event type, its arguments, the policy gate, the
//! limits) and makes its one outbound request, the callback challenge, only
//! after them. The subscription record is the last write, so a failure at
//! any step leaves nothing behind and a retried subscribe is safe: it is an
//! upsert on the same key.

use mcpg_safe_egress::CallbackUrl;
use mcpg_standard_webhooks::WhsecSecret;
use serde_json::{Map, Value};

use super::catalog::EventType;
use super::cursor::CursorScope;
use super::engine::EventsCore;
use super::handler::policy_key;
use super::keys::SealedSecret;
use super::log::ResumePoint;
use super::subscriptions::{
    CreateOutcome, CredentialSnapshot, DeliveryState, FORMAT_VERSION, Grant, HintOp, StartPosition,
    SubscriptionHint, SubscriptionRecord, rfc3339_ms,
};
use super::verifier::{challenge, is_allowlisted, receiver_document_admits};
use crate::config::events::{
    EventReplay, EventsConfig, SubscriberTrust, UnsubscribeUnknown, VerificationMode,
};
use crate::protocol::v_2026_07_28::extensions::events::errors::{
    EventsError, EventsErrorData, FEATURE_INPUT_SCHEMA, ForbiddenData, ForbiddenReason,
    NotFoundKind,
};
use crate::protocol::v_2026_07_28::extensions::events::wire::{
    DeliveryErrorCategory, DeliveryMode, DeliveryStatus, SubscribeEventsParams,
    SubscribeEventsResult, UnsubscribeEventsParams, UnsubscribeEventsResult,
};
use crate::runtime::policy::PolicyRoute;
use crate::runtime::{RequestContext, RequestIdentity, RequestTrustLevel};

/// Largest canonical size of subscription arguments, in bytes.
pub const MAX_ARGUMENTS_BYTES: usize = 4_096;
/// Deepest nesting of subscription arguments.
pub const MAX_ARGUMENTS_DEPTH: usize = 8;
/// What a subscribe answers when the subscription has to be made again.
const STORE_FAULT: &str = "the event subscription store is unavailable; retry";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The key a subscription belongs to: the caller's trust-qualified
/// principal, when its trust meets `floor`.
pub fn subscriber_key(
    identity: &RequestIdentity,
    floor: SubscriberTrust,
) -> Result<String, EventsError> {
    let needed = match floor {
        SubscriberTrust::Verified => RequestTrustLevel::Verified,
        SubscriberTrust::HeaderAsserted => RequestTrustLevel::HeaderAsserted,
    };
    if identity.trust_level() < needed {
        return Err(EventsError::forbidden(ForbiddenReason::Unauthenticated));
    }
    identity
        .synthetic_principal_key()
        .ok_or_else(|| EventsError::forbidden(ForbiddenReason::Unauthenticated))
}

/// The facts about the caller's credential a subscription keeps: the grant
/// and `jti` of a token this gateway minted, whose revocation it learns,
/// and the token's expiry when known, which caps the grant.
pub fn credential_snapshot(ctx: &RequestContext) -> CredentialSnapshot {
    let attributes = ctx.identity.attributes();
    let claims = ctx.inbound_bearer.as_deref().and_then(jwt_claims);
    let minted = ctx.identity.is_gateway_minted();
    let token_exp_s = attributes
        .get("token_exp")
        .and_then(|exp| exp.parse::<u64>().ok())
        .or_else(|| claims.as_ref().and_then(|c| c.exp));
    CredentialSnapshot {
        grant_id: minted
            .then(|| attributes.get("grant_id").cloned())
            .flatten(),
        jti: minted
            .then(|| claims.as_ref().and_then(|c| c.jti.clone()))
            .flatten(),
        token_exp_ms: token_exp_s.map(|s| s.saturating_mul(1_000)),
    }
}

#[derive(serde::Deserialize)]
struct BearerClaims {
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
}

/// The `exp` and `jti` of a JWT bearer. The transport verified the token
/// before the request got here; these only shorten a grant and look up a
/// revocation, so reading them unverified grants nothing.
fn jwt_claims(bearer: &str) -> Option<BearerClaims> {
    use base64::Engine as _;
    let mut parts = bearer.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Check subscription `arguments` against the size and depth bounds and the
/// type's input schema. The message never quotes the arguments.
pub fn check_arguments(ty: &EventType, arguments: &Map<String, Value>) -> Result<(), EventsError> {
    let value = Value::Object(arguments.clone());
    if mcpg_mcp_wire::shared::canonical::canonical_value_bytes(&value).len() > MAX_ARGUMENTS_BYTES {
        return Err(EventsError::invalid_params(format!(
            "arguments must be at most {MAX_ARGUMENTS_BYTES} bytes"
        )));
    }
    if depth(&value) > MAX_ARGUMENTS_DEPTH {
        return Err(EventsError::invalid_params(format!(
            "arguments must nest at most {MAX_ARGUMENTS_DEPTH} levels"
        )));
    }
    if !ty.arguments_are_valid(arguments) {
        return Err(EventsError::invalid_params(
            "arguments do not match the event type's inputSchema",
        ));
    }
    Ok(())
}

fn depth(value: &Value) -> usize {
    match value {
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// The `-32012` (or `-32013`) a denial of the policy gate becomes on an
/// `events/*` method. The reason is a fixed category, never the rule.
pub(crate) fn gate_error(response: crate::protocol::ProtocolHttpResponse) -> EventsError {
    let (code, data) = match response.response {
        crate::protocol::ProtocolResponse::JsonRpcError(error) => {
            (error.error.code, error.error.data)
        }
        _ => (-32603, None),
    };
    let insufficient_scope = data
        .as_ref()
        .and_then(|d| d.get(crate::transports::http::INSUFFICIENT_SCOPE_DATA_KEY))
        .cloned();
    let approval_required = matches!(
        EventsErrorData::parse(code, data.as_ref()),
        Some(EventsErrorData::Forbidden(ForbiddenData {
            reason: Some(ForbiddenReason::ApprovalRequired)
        }))
    );
    match code {
        _ if approval_required => EventsError::forbidden(ForbiddenReason::ApprovalRequired),
        -33001 => EventsError::resource_exhausted("quota", None),
        -32029 => EventsError::resource_exhausted("rate_limit", None),
        -33003 => EventsError::internal("a licence-gated gate is withheld; retry later"),
        // The missing scopes ride along under the transport's key, which
        // turns them into an `insufficient_scope` challenge on the way out.
        -32003 if insufficient_scope.is_some() => {
            EventsError::forbidden(ForbiddenReason::InsufficientScope).with_data_entry(
                crate::transports::http::INSUFFICIENT_SCOPE_DATA_KEY,
                insufficient_scope.unwrap_or_default(),
            )
        }
        -32003 => EventsError::forbidden(ForbiddenReason::Trust),
        -33000 => EventsError::forbidden(ForbiddenReason::PolicyEngine),
        -32005 | -32022 | -32603 => EventsError::forbidden(ForbiddenReason::Policy),
        _ => EventsError::forbidden(ForbiddenReason::Gate),
    }
}

/// `deliveryStatus` of a subscription with `delivery`, while every delivery
/// is (or is not) paused.
pub fn delivery_status(delivery: Option<&DeliveryState>, paused: bool) -> DeliveryStatus {
    let counters = delivery.map(|d| &d.counters);
    let suspended = counters.is_some_and(|c| c.suspended_at_ms.is_some());
    DeliveryStatus {
        active: !paused && !suspended,
        last_delivery_at: counters.and_then(|c| c.last_delivery_at_ms).map(rfc3339_ms),
        last_error: if paused {
            Some(DeliveryErrorCategory::Paused)
        } else {
            counters.and_then(|c| c.last_error)
        },
        failed_since: counters.and_then(|c| c.failed_since_ms).map(rfc3339_ms),
        throttled: None,
        retry_after_ms: None,
    }
}

/// What a subscribe does with an existing record.
enum Existing {
    /// No record, or one whose grant ended: make a new one.
    None,
    /// A live record: refresh it.
    Live(Box<SubscriptionRecord>),
}

impl EventsCore {
    /// The event type `name` offers webhook delivery to `ctx`; `-32011` when
    /// the caller may not see it.
    fn webhook_type(
        &self,
        ctx: &RequestContext,
        name: &str,
    ) -> Result<std::sync::Arc<EventType>, EventsError> {
        self.offered_type(ctx, name, DeliveryMode::Webhook)
    }

    /// The event type `name` offers `mode` to `ctx`; `-32011` when the
    /// caller may not see it.
    pub(crate) fn offered_type(
        &self,
        ctx: &RequestContext,
        name: &str,
        mode: DeliveryMode,
    ) -> Result<std::sync::Arc<EventType>, EventsError> {
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?;
        let catalog = self.catalog();
        let ty = catalog
            .get(name)
            .filter(|ty| {
                runtime.load().surface_is_visible(
                    ctx,
                    &policy_key(&ty.name),
                    PolicyRoute::event(None),
                )
            })
            .cloned()
            .ok_or_else(|| EventsError::not_found(NotFoundKind::Event))?;
        if !ty.offers(mode) {
            return Err(EventsError::unsupported_delivery_mode(mode.as_str()));
        }
        Ok(ty)
    }

    /// `events/subscribe`.
    pub(crate) async fn subscribe_webhook(
        &self,
        ctx: &RequestContext,
        params: SubscribeEventsParams,
    ) -> Result<SubscribeEventsResult, EventsError> {
        let config = self.config();
        if !params.delivery.is_webhook() {
            return Err(EventsError::unsupported_delivery_mode(
                &params.delivery.mode,
            ));
        }
        if !config.webhook.enabled {
            return Err(EventsError::unsupported_delivery_mode(
                DeliveryMode::Webhook.as_str(),
            ));
        }
        let egress = self
            .egress()
            .ok_or_else(|| EventsError::internal("webhook delivery is not ready; retry"))?;
        let url = egress.check_url(&params.delivery.url).map_err(|_| {
            EventsError::invalid_params("delivery.url is not an accepted callback URL")
        })?;
        let signing = params.delivery.secret.signing_secret();
        let principal_key = subscriber_key(&ctx.identity, config.webhook.require_trust)?;
        let ty = self.webhook_type(ctx, &params.name)?;
        check_arguments(&ty, &params.arguments)?;

        let arguments = Value::Object(params.arguments.clone());
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?
            .load_full();
        if runtime.license_state().events_hold.is_some() {
            return Err(EventsError::forbidden(ForbiddenReason::Licence));
        }
        runtime
            .evaluate_surface_gate(
                "event",
                "event.subscribe.pre",
                &policy_key(&ty.name),
                PolicyRoute::event(Some(&arguments)),
                &arguments,
                ctx,
                &Value::Null,
            )
            .await
            .map_err(gate_error)?;

        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let store = &stores.subscriptions;
        let id = store.id_for(&principal_key, url.as_str(), &ty.name, &params.arguments);
        let now = now_ms();
        let credential = credential_snapshot(ctx);
        let grant = self
            .ttl_policy()
            .grant(params.ttl_ms, credential.token_exp_ms, now);

        let mut existing = match store.get(&id).await {
            // A config change ended it: the refresh says why once, and the
            // client then starts over on the type as it is now.
            Ok(Some(record)) if record.ended_by_config() => {
                if let Err(error) = store.delete(&record.id).await {
                    tracing::warn!(error = %error, "ended event subscription could not be removed");
                    return Err(EventsError::internal(STORE_FAULT));
                }
                self.note_subscription(&SubscriptionHint {
                    op: HintOp::Delete,
                    id: record.id.clone(),
                    name: record.name.clone(),
                    expires_at_ms: record.expires_at_ms,
                });
                if record.schema_epoch != ty.schema_epoch {
                    return Err(EventsError::schema_changed(FEATURE_INPUT_SCHEMA));
                }
                Existing::None
            }
            Ok(Some(record)) if !record.is_lapsed_at(now) => Existing::Live(Box::new(record)),
            Ok(_) => Existing::None,
            Err(error) => {
                tracing::warn!(error = %error, "event subscription read failed");
                return Err(EventsError::internal(STORE_FAULT));
            }
        };
        // A concurrent subscribe on the same key can create the record
        // between the read and the create; the second pass refreshes it.
        for _ in 0..2 {
            match existing {
                Existing::Live(record) => {
                    return self
                        .refresh(
                            ctx, &config, &ty, *record, &params, signing, grant, credential,
                        )
                        .await;
                }
                Existing::None => {
                    match self
                        .create(
                            ctx,
                            &config,
                            &ty,
                            &id,
                            &principal_key,
                            &url,
                            &params,
                            &signing,
                            grant,
                            credential.clone(),
                        )
                        .await?
                    {
                        Ok(result) => return Ok(result),
                        Err(winner) => existing = Existing::Live(winner),
                    }
                }
            }
        }
        Err(EventsError::internal(STORE_FAULT))
    }

    /// Refresh the live subscription `record`: a new secret (the previous
    /// one signs on through the grace window), a new grant, a fresh
    /// identity snapshot, and a resumed delivery if it was suspended. The
    /// cursor of the request is a no-op on a live subscription.
    #[allow(clippy::too_many_arguments)]
    async fn refresh(
        &self,
        ctx: &RequestContext,
        config: &EventsConfig,
        ty: &EventType,
        mut record: SubscriptionRecord,
        params: &SubscribeEventsParams,
        signing: WhsecSecret,
        grant: Grant,
        credential: CredentialSnapshot,
    ) -> Result<SubscribeEventsResult, EventsError> {
        if record.revoked.is_some() {
            return Err(EventsError::forbidden(ForbiddenReason::Revoked));
        }
        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let store = &stores.subscriptions;
        let now = now_ms();
        let current = store
            .open_secret(&record.id, &record.secret)
            .map(|s| s.signing_secret());
        let rotated = current.as_ref().is_none_or(|c| !c.same_key(&signing));
        if rotated {
            let previous: Option<SealedSecret> = current.is_some().then(|| record.secret.clone());
            record.previous_secret = previous;
            record.previous_secret_until_ms = record
                .previous_secret
                .as_ref()
                .map(|_| now.saturating_add(config.webhook.secret_rotation_grace_ms));
            record.secret = store.seal_secret(&record.id, &params.delivery.secret);
        } else if record
            .previous_secret_until_ms
            .is_some_and(|until| until <= now)
        {
            record.previous_secret = None;
            record.previous_secret_until_ms = None;
        }
        record.identity = ctx.identity.clone();
        record.credential = credential;
        record.refreshed_at_ms = now;
        record.expires_at_ms = grant.expires_at_ms;
        record.reactivated_at_ms = Some(now);
        if let Err(error) = store.replace(&record).await {
            tracing::warn!(error = %error, "event subscription refresh failed");
            return Err(EventsError::internal(STORE_FAULT));
        }
        self.note_subscription(&SubscriptionHint {
            op: HintOp::Upsert,
            id: record.id.clone(),
            name: record.name.clone(),
            expires_at_ms: record.expires_at_ms,
        });
        let delivery = store.delivery(&record.id).await.ok().flatten();
        let cursor = (ty.replay == EventReplay::Log).then(|| {
            let (epoch, seq) = delivery
                .as_ref()
                .map_or((record.start.epoch, record.start.after_seq), |d| {
                    (d.epoch, d.ack_seq)
                });
            stores.log.seal_cursor(
                epoch,
                ty.schema_epoch,
                seq,
                &CursorScope::new(&ty.source_key, &Value::Object(record.arguments.clone())),
            )
        });
        let paused = self.operator_paused().await;
        let mut status = delivery_status(delivery.as_ref(), paused);
        // The refresh lifts a suspension; the owner resumes delivery from
        // the watermark.
        status.active = !paused;
        let audit = if rotated {
            "secret_rotated"
        } else {
            "refreshed"
        };
        self.audit_subscribe(ctx, &record, audit).await;
        metrics::counter!("mcpg_events_subscribe_total", "event" => ty.name.clone(), "outcome" => audit)
            .increment(1);
        let mut result =
            SubscribeEventsResult::new(record.id, grant.refresh_before(), cursor, false);
        result.delivery_status = Some(status);
        Ok(result)
    }

    /// Make a new subscription after the limits and the callback
    /// verification. `Ok(Err(record))` hands back the live record a
    /// concurrent subscribe created first.
    #[allow(clippy::too_many_arguments)]
    async fn create(
        &self,
        ctx: &RequestContext,
        config: &EventsConfig,
        ty: &EventType,
        id: &str,
        principal_key: &str,
        url: &CallbackUrl,
        params: &SubscribeEventsParams,
        signing: &WhsecSecret,
        grant: Grant,
        credential: CredentialSnapshot,
    ) -> Result<Result<SubscribeEventsResult, Box<SubscriptionRecord>>, EventsError> {
        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let store = &stores.subscriptions;
        self.check_limits(config, ty, principal_key, url).await?;
        let holder = super::federated::LeaseHolder {
            principal_key,
            identity: &ctx.identity,
            arguments: &params.arguments,
        };
        self.check_plan_readers(ty, &holder).await?;
        let now = now_ms();
        let verified_at = self
            .verify_callback(config, principal_key, url, id, signing, now)
            .await?;

        let scope = CursorScope::new(&ty.source_key, &Value::Object(params.arguments.clone()));
        let point = match ty.replay {
            EventReplay::None => {
                let head = stores
                    .log
                    .bounds(&ty.source_key)
                    .await
                    .map_err(|_| EventsError::internal(STORE_FAULT))?;
                ResumePoint {
                    epoch: head.epoch,
                    after_seq: head.head,
                    truncated: false,
                }
            }
            EventReplay::Log => match stores
                .log
                .resume(
                    &ty.source_key,
                    params.cursor.as_deref(),
                    &scope,
                    ty.schema_epoch,
                    params.max_age_ms,
                )
                .await
            {
                Ok(Ok(point)) => point,
                Ok(Err(_)) => return Err(EventsError::schema_changed(FEATURE_INPUT_SCHEMA)),
                Err(error) => {
                    tracing::warn!(error = %error, "event log read failed on subscribe");
                    return Err(EventsError::internal(STORE_FAULT));
                }
            },
        };
        let record = SubscriptionRecord {
            v: FORMAT_VERSION,
            id: id.to_owned(),
            principal_key: principal_key.to_owned(),
            identity: ctx.identity.clone(),
            credential,
            url: url.as_str().to_owned(),
            host: url.host().to_owned(),
            name: ty.name.clone(),
            arguments: params.arguments.clone(),
            secret: store.seal_secret(id, &params.delivery.secret),
            previous_secret: None,
            previous_secret_until_ms: None,
            created_at_ms: now,
            refreshed_at_ms: now,
            expires_at_ms: grant.expires_at_ms,
            verified_at_ms: Some(verified_at),
            start: StartPosition {
                epoch: point.epoch,
                after_seq: point.after_seq,
                truncated: point.truncated,
            },
            schema_epoch: ty.schema_epoch,
            reactivated_at_ms: None,
            operator_suspended_at_ms: None,
            revoked: None,
        };
        match store.create(&record).await {
            Ok(CreateOutcome::Created { .. }) => {}
            Ok(CreateOutcome::Exists(winner)) => return Ok(Err(winner)),
            Err(error) => {
                tracing::warn!(error = %error, "event subscription create failed");
                return Err(EventsError::internal(STORE_FAULT));
            }
        }
        self.note_subscription(&SubscriptionHint {
            op: HintOp::Upsert,
            id: record.id.clone(),
            name: record.name.clone(),
            expires_at_ms: record.expires_at_ms,
        });
        self.audit_subscribe(ctx, &record, "created").await;
        metrics::counter!("mcpg_events_subscribe_total", "event" => ty.name.clone(), "outcome" => "created")
            .increment(1);
        let cursor = (ty.replay == EventReplay::Log).then(|| {
            stores
                .log
                .seal_cursor(point.epoch, ty.schema_epoch, point.after_seq, &scope)
        });
        let paused = self.operator_paused().await;
        let mut result =
            SubscribeEventsResult::new(record.id, grant.refresh_before(), cursor, point.truncated);
        result.delivery_status = Some(delivery_status(None, paused));
        Ok(Ok(result))
    }

    async fn check_limits(
        &self,
        config: &EventsConfig,
        ty: &EventType,
        principal_key: &str,
        url: &CallbackUrl,
    ) -> Result<(), EventsError> {
        let limits = &config.webhook.limits;
        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let usage = stores
            .subscriptions
            .principal_usage(principal_key)
            .await
            .map_err(|_| EventsError::internal(STORE_FAULT))?;
        if usage.subscriptions >= limits.per_principal {
            return Err(EventsError::resource_exhausted(
                "subscriptions",
                Some(limits.per_principal),
            ));
        }
        let host = stores.keys.key_hash("callback-host", url.host().as_bytes());
        if !usage.hosts.contains(&host)
            && usage.hosts.len() as u64 >= limits.per_principal_callback_hosts
        {
            return Err(EventsError::resource_exhausted(
                "callback_hosts",
                Some(limits.per_principal_callback_hosts),
            ));
        }
        let (of_type, total) = self.live_counts(&ty.name, now_ms());
        if of_type as u64 >= limits.per_type {
            return Err(EventsError::resource_exhausted(
                "subscriptions_per_type",
                Some(limits.per_type),
            ));
        }
        if total as u64 >= limits.total {
            return Err(EventsError::resource_exhausted(
                "subscriptions_total",
                Some(limits.total),
            ));
        }
        Ok(())
    }

    /// Prove that `url` wants deliveries for `principal_key`, reusing a
    /// recent pass. Returns when the pass happened.
    async fn verify_callback(
        &self,
        config: &EventsConfig,
        principal_key: &str,
        url: &CallbackUrl,
        id: &str,
        signing: &WhsecSecret,
        now: u64,
    ) -> Result<u64, EventsError> {
        let verification = &config.webhook.verification;
        if is_allowlisted(verification, url.host()) {
            return Ok(now);
        }
        let stores = self
            .stores()
            .ok_or_else(|| EventsError::internal(STORE_FAULT))?;
        let store = &stores.subscriptions;
        match store.verified_at(principal_key, url.as_str()).await {
            Ok(Some(at)) => return Ok(at),
            Ok(None) => {}
            Err(_) => return Err(EventsError::internal(STORE_FAULT)),
        }
        let exhausted = || {
            EventsError::resource_exhausted(
                "callback_verifications",
                Some(verification.per_host_per_min),
            )
        };
        let _slot = self
            .verifying_hosts()
            .take(url.host(), verification.per_host_in_flight)
            .ok_or_else(exhausted)?;
        match store
            .take_verification_slot(url.host(), verification.per_host_per_min, now)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(exhausted()),
            Err(_) => return Err(EventsError::internal(STORE_FAULT)),
        }
        let egress = self
            .egress()
            .ok_or_else(|| EventsError::internal("webhook delivery is not ready; retry"))?;
        let timeout = std::time::Duration::from_millis(verification.timeout_ms.max(1));
        // A receiver document that names the callback stands in for the
        // challenge; without one, the challenge decides.
        let documented = verification.modes.contains(&VerificationMode::WellKnown)
            && receiver_document_admits(&egress, url, timeout)
                .await
                .unwrap_or(false);
        let outcome = if documented {
            Ok(())
        } else {
            challenge(&egress, url, id, signing, timeout, now / 1_000).await
        };
        let label = match outcome {
            Ok(()) if documented => "documented",
            Ok(()) => "passed",
            Err(category) => category.as_str(),
        };
        metrics::counter!("mcpg_events_verifications_total", "outcome" => label).increment(1);
        self.audit_verification(principal_key, url, label).await;
        match outcome {
            Ok(()) => {
                let ttl = std::time::Duration::from_millis(verification.cache_ttl_ms.max(1));
                if let Err(error) = store
                    .remember_verification(principal_key, url.as_str(), now, ttl)
                    .await
                {
                    tracing::debug!(error = %error, "callback verification could not be cached");
                }
                Ok(now)
            }
            Err(category) => {
                metrics::counter!("mcpg_events_verification_failures_total", "category" => category.as_str())
                    .increment(1);
                Err(EventsError::callback_endpoint(category))
            }
        }
    }

    /// `events/unsubscribe`. Idempotent: an unknown key answers `{}` unless
    /// `unsubscribe_unknown: not_found`. Another principal's subscription
    /// has another key, so it is never reachable.
    pub(crate) async fn unsubscribe_webhook(
        &self,
        ctx: &RequestContext,
        params: UnsubscribeEventsParams,
    ) -> Result<UnsubscribeEventsResult, EventsError> {
        let config = self.config();
        if let Some(mode) = params.delivery.mode.as_deref()
            && mode != DeliveryMode::Webhook.as_str()
        {
            return Err(EventsError::unsupported_delivery_mode(mode));
        }
        let principal_key = subscriber_key(&ctx.identity, config.webhook.require_trust)?;
        let unknown = |kind: NotFoundKind| match config.unsubscribe_unknown {
            UnsubscribeUnknown::Ok => Ok(UnsubscribeEventsResult::default()),
            UnsubscribeUnknown::NotFound => Err(EventsError::not_found(kind)),
        };
        // The id is over the normalized URL, which needs no policy: a host
        // denied since the subscribe can still be unsubscribed.
        let Ok(url) = url::Url::parse(&params.delivery.url) else {
            return Err(EventsError::invalid_params("delivery.url is not a URL"));
        };
        let runtime = self
            .runtime()
            .ok_or_else(|| EventsError::internal("the gateway is shutting down"))?;
        if !runtime.load().surface_is_visible(
            ctx,
            &policy_key(&params.name),
            PolicyRoute::event(None),
        ) {
            return Ok(UnsubscribeEventsResult::default());
        }
        let Some(stores) = self.stores() else {
            return unknown(NotFoundKind::Subscription);
        };
        let id = stores.subscriptions.id_for(
            &principal_key,
            url.as_str(),
            &params.name,
            &params.arguments,
        );
        match stores.subscriptions.delete(&id).await {
            Ok(Some(record)) => {
                self.note_subscription(&SubscriptionHint {
                    op: HintOp::Delete,
                    id: record.id.clone(),
                    name: record.name.clone(),
                    expires_at_ms: record.expires_at_ms,
                });
                self.audit_unsubscribe(ctx, &record).await;
                metrics::counter!("mcpg_events_unsubscribe_total", "outcome" => "deleted")
                    .increment(1);
                Ok(UnsubscribeEventsResult::default())
            }
            Ok(None) => {
                metrics::counter!("mcpg_events_unsubscribe_total", "outcome" => "unknown")
                    .increment(1);
                if self.catalog().get(&params.name).is_none() {
                    unknown(NotFoundKind::Event)
                } else {
                    unknown(NotFoundKind::Subscription)
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "event unsubscribe failed");
                Err(EventsError::internal(STORE_FAULT))
            }
        }
    }
}

#[cfg(test)]
#[path = "webhook_tests.rs"]
mod tests;
