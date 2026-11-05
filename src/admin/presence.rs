//! `GET /admin/v1/subscriptions`: who holds what, across every replica,
//! read from the shared stores.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::runtime::GatewayRuntime;
use crate::runtime::events::EventsCore;

/// Most rows one page returns.
const MAX_PAGE: usize = 500;
/// Most holders of one kind one scan reads.
const SCAN_LIMIT: usize = 10_000;

/// Query of `GET /admin/v1/subscriptions`. Exactly one of `uri`, `prefix`
/// and `event`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceQuery {
    pub uri: Option<String>,
    pub prefix: Option<String>,
    pub event: Option<String>,
    /// `resource`, `stream`, `webhook` or `poll`.
    pub kind: Option<String>,
    /// The last `id` of the previous page.
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    /// Counts per kind instead of rows.
    #[serde(default)]
    pub count: bool,
}

/// Why a query was refused.
#[derive(Debug)]
pub enum PresenceError {
    BadQuery(&'static str),
    Store(String),
}

fn row_id(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0x1f]);
    }
    hex::encode(&hasher.finalize()[..16])
}

fn rfc3339_ms(ms: u64) -> Value {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map_or(Value::Null, |at| {
            json!(at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        })
}

/// Rows (or counts) for `query`, ordered by `id`.
pub async fn subscriptions(
    runtime: &GatewayRuntime,
    events: Option<Arc<EventsCore>>,
    query: &PresenceQuery,
) -> Result<Value, PresenceError> {
    let selectors = [&query.uri, &query.prefix, &query.event]
        .iter()
        .filter(|s| s.is_some())
        .count();
    if selectors != 1 {
        return Err(PresenceError::BadQuery(
            "give exactly one of uri, prefix or event",
        ));
    }
    if let Some(kind) = query.kind.as_deref()
        && !matches!(kind, "resource" | "stream" | "webhook" | "poll")
    {
        return Err(PresenceError::BadQuery(
            "kind is one of resource, stream, webhook, poll",
        ));
    }
    let wants = |kind: &str| query.kind.as_deref().is_none_or(|k| k == kind);
    let registry = runtime.plugin_registry();
    let mut rows: Vec<Value> = Vec::new();
    let mut pollers_untracked = false;

    if query.event.is_none() && wants("resource") {
        let store = runtime.subscription_store();
        let uris = match store.watch_state() {
            Some(state) => state
                .demanded()
                .await
                .map_err(|e| PresenceError::Store(e.to_string()))?,
            None => Vec::new(),
        };
        for uri in uris
            .into_iter()
            .filter(|uri| match (&query.uri, &query.prefix) {
                (Some(exact), _) => uri == exact,
                (_, Some(prefix)) => uri.starts_with(prefix.as_str()),
                _ => false,
            })
        {
            for (session, identity) in store.subscribers_with_identity(&uri) {
                let identity = identity.unwrap_or_default();
                let principal = identity
                    .principal
                    .clone()
                    .map(|p| registry.digest_audit_identity(p));
                let client = identity
                    .client_name
                    .as_ref()
                    .map(|name| json!({ "name": name, "version": identity.client_version }));
                rows.push(json!({
                    "id": row_id(&["resource", &uri, &session]),
                    "kind": "resource",
                    "uri": uri,
                    "event": null,
                    "principal": principal,
                    "client": client,
                    "transport": identity.transport,
                    "since": identity.subscribed_at,
                    "last_seen": identity.subscribed_at,
                    "node": identity.node,
                }));
            }
        }
    }

    if let Some(name) = query.event.as_deref() {
        let core = events.ok_or(PresenceError::BadQuery("MCP Events are not enabled"))?;
        let stores = core
            .stores()
            .ok_or_else(|| PresenceError::Store("events stores are not ready".into()))?;
        let ty = core.catalog().get(name).cloned();
        let heartbeat = ty.as_ref().is_some_and(|t| t.audit.poll_heartbeat_secs > 0);

        let presence_row =
            |kind: &str, id: String, p: &crate::runtime::events::poll::PresenceRow| {
                let mut row = json!({
                    "id": id,
                    "kind": kind,
                    "uri": null,
                    "event": name,
                    "principal": registry.digest_audit_identity(p.principal.clone()),
                    "client": p.client,
                    "transport": p.transport,
                    "since": rfc3339_ms(p.since_ms),
                    "last_seen": rfc3339_ms(p.refreshed_ms),
                    "node": p.node,
                });
                if let Some(obj) = row.as_object_mut() {
                    obj.extend(p.arguments.clone());
                }
                row
            };

        if wants("stream") {
            for entry in stores
                .leases
                .list_streams(SCAN_LIMIT)
                .await
                .map_err(|e| PresenceError::Store(e.to_string()))?
                .into_iter()
                .filter(|e| e.name == name)
            {
                if let Some(p) = &entry.presence {
                    rows.push(presence_row("stream", row_id(&["stream", &entry.id]), p));
                }
            }
        }
        if wants("poll") {
            if heartbeat {
                for entry in stores
                    .leases
                    .list_pollers(SCAN_LIMIT)
                    .await
                    .map_err(|e| PresenceError::Store(e.to_string()))?
                    .into_iter()
                    .filter(|e| e.name == name)
                {
                    if let Some(p) = &entry.presence {
                        rows.push(presence_row("poll", row_id(&["poll", &entry.id]), p));
                    }
                }
            } else {
                pollers_untracked = true;
            }
        }
        if wants("webhook") {
            let mode = ty.as_ref().map(|t| t.audit.arguments).unwrap_or_default();
            for entry in stores
                .subscriptions
                .list_type(name)
                .await
                .map_err(|e| PresenceError::Store(e.to_string()))?
            {
                let Ok(Some(record)) = stores.subscriptions.get(&entry.id).await else {
                    continue;
                };
                let principal = registry.digest_audit_identity(
                    crate::runtime::plugin_identity_from_request_identity(&record.identity),
                );
                let mut row = json!({
                    "id": row_id(&["webhook", &record.id]),
                    "kind": "webhook",
                    "uri": null,
                    "event": name,
                    "principal": principal,
                    "client": null,
                    "transport": "webhook",
                    "since": rfc3339_ms(record.created_at_ms),
                    "last_seen": rfc3339_ms(record.refreshed_at_ms),
                    "node": null,
                });
                if let Some(obj) = row.as_object_mut() {
                    obj.extend(crate::runtime::events::audit::arguments_fields(
                        Some(&stores.keys),
                        mode,
                        &record.arguments,
                    ));
                }
                rows.push(row);
            }
        }
    }

    rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    if query.count {
        let mut counts = serde_json::Map::new();
        for row in &rows {
            let kind = row["kind"].as_str().unwrap_or_default().to_owned();
            let n = counts.get(&kind).and_then(Value::as_u64).unwrap_or(0) + 1;
            counts.insert(kind, json!(n));
        }
        let mut out = json!({ "count": counts });
        if pollers_untracked {
            out["pollers"] = json!("untracked");
        }
        return Ok(out);
    }
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_PAGE);
    let page: Vec<Value> = rows
        .into_iter()
        .filter(|row| {
            query
                .cursor
                .as_deref()
                .is_none_or(|after| row["id"].as_str().is_some_and(|id| id > after))
        })
        .take(limit + 1)
        .collect();
    let more = page.len() > limit;
    let page: Vec<Value> = page.into_iter().take(limit).collect();
    let next = if more {
        page.last()
            .and_then(|row| row["id"].as_str())
            .map(str::to_owned)
    } else {
        None
    };
    let mut out = json!({ "subscriptions": page, "cursor": next });
    if pollers_untracked {
        out["pollers"] = json!("untracked");
    }
    Ok(out)
}
