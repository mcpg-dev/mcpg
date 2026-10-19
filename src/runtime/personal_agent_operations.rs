//! The operations extension (version 1) of the Personal Agent Protocol: a
//! tool listed in `personal_agent.operations` proposes an operation instead
//! of acting, the Personal Agent confirms one revision at the operations
//! endpoint, and the gateway performs it at most once across replicas.
//!
//! Records live in a key-value store every replica shares. A short lease
//! serialises the state changes of one operation, so a confirm and a new
//! revision cannot interleave; a `put_if_absent` claim lets one confirm,
//! and only one, run the action.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use mcpg_cluster_api::KeyValueStore;
use mcpg_expr::{DynamicValue, ExprContext};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::personal_agent::{OperationToolConfig, OperationsConfig};
use crate::runtime::personal_agent::PersonalAgentCaller;

/// Key prefix of an operation's record.
const RECORD_PREFIX: &str = "pap-op:";
/// Key prefix of an action key's current operation.
const ACTION_PREFIX: &str = "pap-op-action:";
/// How long one state change may hold an operation's lease.
const LOCK_TTL: Duration = Duration::from_secs(10);
/// How long a state change waits for the lease.
const LOCK_WAIT: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(25);
/// How long an `in_progress` operation is kept at least, past its last
/// change, whatever `retain_final_secs` says.
const MIN_IN_PROGRESS_RETENTION: Duration = Duration::from_secs(30 * 86_400);
/// How often an in-process store drops its expired records.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Where an operation is (operations §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Proposed,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

impl OperationState {
    /// A final operation never changes state again.
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Proposed | Self::InProgress)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::InProgress => "in_progress",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

/// How the Personal Agent got the User's approval (operations §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedBy {
    User,
    StandingPermission,
}

impl ApprovedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::StandingPermission => "standing_permission",
        }
    }
}

/// A recorded confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    pub revision: u32,
    pub approved_by: ApprovedBy,
    pub confirmed_at: DateTime<Utc>,
}

/// What happened, once final.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Who may use an operation (operations §3.2): the proposing Session, and,
/// when it was signed in, every Session of the same Personal Agent and User
/// signed in to the same account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub client_id: String,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub account: Option<String>,
}

impl Owner {
    /// The owner of what `caller` proposes; `None` for a plain MCP client,
    /// and for a Personal Agent with neither a Session nor an account, which
    /// no request could use again.
    fn of(caller: &PersonalAgentCaller) -> Option<Self> {
        let owner = Self {
            client_id: caller.client_id.clone()?,
            session_id: caller.session_id.clone(),
            user_id: caller.user_id.clone(),
            account: caller.signed_in.then(|| caller.account.clone()).flatten(),
        };
        (owner.session_id.is_some() || owner.account.is_some()).then_some(owner)
    }

    /// Whether `caller` may read, confirm and cancel the operation.
    pub fn admits(&self, caller: &PersonalAgentCaller) -> bool {
        if caller.client_id.as_deref() != Some(self.client_id.as_str()) {
            return false;
        }
        let same_session = self.session_id.is_some() && caller.session_id == self.session_id;
        let same_account = self.account.is_some()
            && caller.signed_in
            && caller.account == self.account
            && caller.user_id == self.user_id;
        same_session || same_account
    }

    /// What identifies the owner for an action key: the account when
    /// signed in, else the Session.
    fn scope(&self) -> String {
        match &self.account {
            Some(account) => format!(
                "account\u{1f}{}\u{1f}{}\u{1f}{account}",
                self.client_id,
                self.user_id.as_deref().unwrap_or_default()
            ),
            None => format!(
                "session\u{1f}{}\u{1f}{}",
                self.client_id,
                self.session_id.as_deref().unwrap_or_default()
            ),
        }
    }
}

/// An operation as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: String,
    pub tool: String,
    pub revision: u32,
    pub state: OperationState,
    pub summary: String,
    pub terms: Value,
    pub expires_at: DateTime<Utc>,
    pub user_approval_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<Confirmation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<OperationResult>,
    pub owner: Owner,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_key: Option<String>,
    pub updated_at: DateTime<Utc>,
}

impl OperationRecord {
    /// The operation as the extension shows it (operations §3).
    pub fn wire(&self) -> Value {
        let mut operation = json!({
            "operation_id": self.operation_id,
            "revision": self.revision,
            "state": self.state.as_str(),
            "summary": self.summary,
            "terms": self.terms,
            "user_approval_required": self.user_approval_required,
            "confirmation": self.confirmation.as_ref().map(|confirmation| json!({
                "revision": confirmation.revision,
                "approved_by": confirmation.approved_by.as_str(),
                "confirmed_at": confirmation.confirmed_at.to_rfc3339(),
            })),
            "result": self.result,
        });
        if self.state == OperationState::Proposed {
            operation["expires_at"] = json!(self.expires_at.to_rfc3339());
        }
        if let Some(url) = &self.url {
            operation["url"] = json!(url);
        }
        operation
    }

    /// Mark a `proposed` operation past its `expires_at` as `expired`;
    /// whether it changed.
    fn expire_if_due(&mut self, now: DateTime<Utc>) -> bool {
        if self.state == OperationState::Proposed && now > self.expires_at {
            self.state = OperationState::Expired;
            self.result = Some(OperationResult {
                summary: "Not confirmed before it expired. Nothing was done.".to_owned(),
                data: None,
            });
            self.updated_at = now;
            return true;
        }
        false
    }
}

/// Why an operation request is refused (operations §9).
#[derive(Debug)]
pub enum OperationError {
    /// 404 `operation_not_found`: unknown, or the Session cannot use it.
    NotFound,
    /// 409 `terms_changed`, with the current operation.
    TermsChanged(Box<OperationRecord>),
    /// 403 `user_approval_required`.
    UserApprovalRequired,
    /// The store could not be read or written, or the lease could not be
    /// taken: retry.
    Unavailable(String),
    /// The configured template could not be rendered for these arguments.
    Template(String),
}

/// How a confirmed action ended.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionOutcome {
    Succeeded {
        summary: String,
        data: Option<Value>,
    },
    Failed {
        summary: String,
    },
    /// Whether the action took effect is not known: the operation stays
    /// `in_progress` (operations §6).
    Unknown {
        reason: String,
    },
}

/// What a confirm made of the operation.
#[derive(Debug)]
pub enum ConfirmOutcome {
    /// Confirmed now and moved to `in_progress`: the caller runs the action.
    Run(OperationRecord),
    /// Not `proposed` (or expired): returned as it is, nothing else done.
    AsIs(OperationRecord),
}

/// One operations tool, its templates compiled.
struct CompiledTool {
    config: OperationToolConfig,
    summary: DynamicValue<String>,
    action_key: Option<DynamicValue<String>>,
    url: Option<DynamicValue<String>>,
}

/// `personal_agent.operations`, resolved over its store.
pub struct OperationsService {
    config: OperationsConfig,
    tools: HashMap<String, CompiledTool>,
    kv: Arc<dyn KeyValueStore>,
    process_local: bool,
}

impl std::fmt::Debug for OperationsService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationsService")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A held lease on one operation; release it with
/// [`OperationsService::release`].
struct Lease {
    key: String,
    token: String,
}

impl OperationsService {
    /// Operations whose records live in `kv`, a store every replica shares.
    pub fn from_config(
        config: &OperationsConfig,
        kv: Arc<dyn KeyValueStore>,
    ) -> anyhow::Result<Self> {
        Self::build(config, kv, false)
    }

    /// Operations whose records live in this process: the store of
    /// `previous` when it is in-process too, so a reload keeps them, else a
    /// new one.
    pub fn in_process(config: &OperationsConfig, previous: Option<&Self>) -> anyhow::Result<Self> {
        let kv = match previous.filter(|previous| previous.process_local) {
            Some(previous) => Arc::clone(&previous.kv),
            None => {
                let kv = crate::builtins::cluster_primitives::MemoryKv::new();
                // Final records are never touched again, so only a sweep
                // reclaims them.
                let kv = if tokio::runtime::Handle::try_current().is_ok() {
                    kv.with_sweep(SWEEP_INTERVAL)
                } else {
                    kv
                };
                Arc::new(kv) as Arc<dyn KeyValueStore>
            }
        };
        Self::build(config, kv, true)
    }

    fn build(
        config: &OperationsConfig,
        kv: Arc<dyn KeyValueStore>,
        process_local: bool,
    ) -> anyhow::Result<Self> {
        let compile = |template: &str| DynamicValue::<String>::parse(template);
        let mut tools = HashMap::new();
        for tool in &config.tools {
            tools.insert(
                tool.tool.clone(),
                CompiledTool {
                    config: tool.clone(),
                    summary: compile(&tool.summary)?,
                    action_key: tool.action_key.as_deref().map(compile).transpose()?,
                    url: tool.url.as_deref().map(compile).transpose()?,
                },
            );
        }
        Ok(Self {
            config: config.clone(),
            tools,
            kv,
            process_local,
        })
    }

    pub fn config(&self) -> &OperationsConfig {
        &self.config
    }

    /// Whether the records live in this process only.
    pub fn is_process_local(&self) -> bool {
        self.process_local
    }

    /// Whether `other` keeps its records in the same store.
    pub fn shares_store_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.kv, &other.kv)
    }

    pub fn is_operation_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    /// Propose `tool` with `arguments` for `caller`, a Personal Agent: a new
    /// operation, or, for the same action key while its operation is
    /// `proposed`, that operation as it is (equal terms) or its next
    /// revision.
    pub async fn propose(
        &self,
        tool: &str,
        arguments: &Value,
        caller: &PersonalAgentCaller,
    ) -> Result<OperationRecord, OperationError> {
        let compiled = self.tools.get(tool).ok_or(OperationError::NotFound)?;
        let owner = Owner::of(caller).ok_or(OperationError::NotFound)?;
        let expr = ExprContext {
            arguments: arguments.clone(),
            tool_name: tool.to_owned(),
            ..ExprContext::default()
        };
        let render = |template: &DynamicValue<String>, field: &str| {
            template
                .resolve(&expr)
                .map_err(|error| OperationError::Template(format!("{field}: {error:#}")))
        };
        let summary = render(&compiled.summary, "summary")?;
        let action_key = compiled
            .action_key
            .as_ref()
            .map(|template| render(template, "action_key"))
            .transpose()?;
        let url = compiled
            .url
            .as_ref()
            .map(|template| render(template, "url"))
            .transpose()?;
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::seconds(
                i64::try_from(compiled.config.expires_after_secs).unwrap_or(i64::MAX),
            );

        if let Some(key) = &action_key {
            let index = action_index_key(&owner, tool, key);
            if let Some(existing) = self.get_text(&index).await? {
                let lease = self.acquire(&existing).await?;
                let revised = self
                    .revise(
                        &existing,
                        caller,
                        arguments,
                        &summary,
                        url.as_deref(),
                        expires_at,
                        now,
                    )
                    .await;
                self.release(lease).await;
                if let Some(record) = revised? {
                    return Ok(record);
                }
            }
        }

        let record = OperationRecord {
            operation_id: format!("op_{}", uuid::Uuid::new_v4().simple()),
            tool: tool.to_owned(),
            revision: 1,
            state: OperationState::Proposed,
            summary,
            terms: arguments.clone(),
            expires_at,
            user_approval_required: compiled.config.user_approval_required,
            url,
            confirmation: None,
            result: None,
            owner: owner.clone(),
            action_key: action_key.clone(),
            updated_at: now,
        };
        self.save(&record).await?;
        if let Some(key) = &action_key {
            let index = action_index_key(&owner, tool, key);
            self.kv
                .put(
                    &index,
                    Bytes::from(record.operation_id.clone()),
                    Some(self.retention(&record)),
                )
                .await
                .map_err(|error| OperationError::Unavailable(error.to_string()))?;
        }
        Ok(record)
    }

    /// Under the lease of `id`: the operation as it is when its terms equal
    /// `arguments`, its next revision when they differ, or `None` when it
    /// is not a `proposed` operation `caller` may use.
    #[allow(clippy::too_many_arguments)]
    async fn revise(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
        arguments: &Value,
        summary: &str,
        url: Option<&str>,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Option<OperationRecord>, OperationError> {
        let Some(mut record) = self.load(id).await? else {
            return Ok(None);
        };
        if record.expire_if_due(now) {
            self.save(&record).await?;
        }
        if record.state != OperationState::Proposed || !record.owner.admits(caller) {
            return Ok(None);
        }
        if &record.terms == arguments {
            return Ok(Some(record));
        }
        record.revision += 1;
        record.terms = arguments.clone();
        record.summary = summary.to_owned();
        record.url = url.map(str::to_owned);
        record.expires_at = expires_at;
        record.updated_at = now;
        self.save(&record).await?;
        Ok(Some(record))
    }

    /// The operation `id`, for `caller`; a `proposed` one past its
    /// `expires_at` is `expired`.
    pub async fn read(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
    ) -> Result<OperationRecord, OperationError> {
        let record = self.load(id).await?.ok_or(OperationError::NotFound)?;
        if !record.owner.admits(caller) {
            return Err(OperationError::NotFound);
        }
        if record.state == OperationState::Proposed && Utc::now() > record.expires_at {
            let lease = self.acquire(id).await?;
            let expired = self.expire(id).await;
            self.release(lease).await;
            return expired;
        }
        Ok(record)
    }

    async fn expire(&self, id: &str) -> Result<OperationRecord, OperationError> {
        let mut record = self.load(id).await?.ok_or(OperationError::NotFound)?;
        if record.expire_if_due(Utc::now()) {
            self.save(&record).await?;
        }
        Ok(record)
    }

    /// Confirm `revision` of `id` for `caller` with `approved_by`
    /// (operations §5.2): `Run` when it is confirmed now and the caller is to
    /// perform it; `AsIs` when it is not `proposed`, which a repeated
    /// confirm finds.
    pub async fn confirm(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
        revision: u32,
        approved_by: ApprovedBy,
    ) -> Result<ConfirmOutcome, OperationError> {
        let lease = self.acquire(id).await?;
        let outcome = self.confirm_held(id, caller, revision, approved_by).await;
        self.release(lease).await;
        outcome
    }

    async fn confirm_held(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
        revision: u32,
        approved_by: ApprovedBy,
    ) -> Result<ConfirmOutcome, OperationError> {
        let now = Utc::now();
        let mut record = self.load(id).await?.ok_or(OperationError::NotFound)?;
        if !record.owner.admits(caller) {
            return Err(OperationError::NotFound);
        }
        if record.expire_if_due(now) {
            self.save(&record).await?;
        }
        if record.state != OperationState::Proposed {
            return Ok(ConfirmOutcome::AsIs(record));
        }
        if revision != record.revision {
            return Err(OperationError::TermsChanged(Box::new(record)));
        }
        if approved_by == ApprovedBy::StandingPermission && record.user_approval_required {
            return Err(OperationError::UserApprovalRequired);
        }
        let claimed = self
            .kv
            .put_if_absent(
                &run_key(id),
                Bytes::from(revision.to_string()),
                Some(MIN_IN_PROGRESS_RETENTION),
            )
            .await
            .map_err(|error| OperationError::Unavailable(error.to_string()))?;
        if !claimed {
            // Another confirm runs it; this one returns what is recorded.
            let current = self.load(id).await?.ok_or(OperationError::NotFound)?;
            return Ok(ConfirmOutcome::AsIs(current));
        }
        record.state = OperationState::InProgress;
        record.confirmation = Some(Confirmation {
            revision,
            approved_by,
            confirmed_at: now,
        });
        record.updated_at = now;
        self.save(&record).await?;
        Ok(ConfirmOutcome::Run(record))
    }

    /// Record how the action of `id` ended. An unknown outcome leaves it
    /// `in_progress`.
    pub async fn finish(
        &self,
        id: &str,
        outcome: ExecutionOutcome,
    ) -> Result<OperationRecord, OperationError> {
        let lease = self.acquire(id).await?;
        let finished = self.finish_held(id, outcome).await;
        self.release(lease).await;
        finished
    }

    async fn finish_held(
        &self,
        id: &str,
        outcome: ExecutionOutcome,
    ) -> Result<OperationRecord, OperationError> {
        let mut record = self.load(id).await?.ok_or(OperationError::NotFound)?;
        if record.state != OperationState::InProgress {
            return Ok(record);
        }
        match outcome {
            ExecutionOutcome::Succeeded { summary, data } => {
                record.state = OperationState::Succeeded;
                record.result = Some(OperationResult { summary, data });
            }
            ExecutionOutcome::Failed { summary } => {
                record.state = OperationState::Failed;
                record.result = Some(OperationResult {
                    summary,
                    data: None,
                });
            }
            ExecutionOutcome::Unknown { .. } => return Ok(record),
        }
        record.updated_at = Utc::now();
        self.save(&record).await?;
        Ok(record)
    }

    /// Cancel `id` for `caller` (operations §7): a `proposed` operation
    /// becomes `cancelled`; any other is returned as it is, since the gateway
    /// cannot stop an action it has handed to a backend.
    pub async fn cancel(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
    ) -> Result<OperationRecord, OperationError> {
        let lease = self.acquire(id).await?;
        let cancelled = self.cancel_held(id, caller).await;
        self.release(lease).await;
        cancelled
    }

    async fn cancel_held(
        &self,
        id: &str,
        caller: &PersonalAgentCaller,
    ) -> Result<OperationRecord, OperationError> {
        let now = Utc::now();
        let mut record = self.load(id).await?.ok_or(OperationError::NotFound)?;
        if !record.owner.admits(caller) {
            return Err(OperationError::NotFound);
        }
        if record.expire_if_due(now) {
            self.save(&record).await?;
        }
        if record.state == OperationState::Proposed {
            record.state = OperationState::Cancelled;
            record.result = Some(OperationResult {
                summary: "Declined before confirmation. Nothing was done.".to_owned(),
                data: None,
            });
            record.updated_at = now;
            self.save(&record).await?;
        }
        Ok(record)
    }

    async fn load(&self, id: &str) -> Result<Option<OperationRecord>, OperationError> {
        let Some(entry) = self
            .kv
            .get(&record_key(id))
            .await
            .map_err(|error| OperationError::Unavailable(error.to_string()))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&entry.bytes)
            .map(Some)
            .map_err(|error| {
                OperationError::Unavailable(format!("a stored operation does not parse: {error}"))
            })
    }

    async fn save(&self, record: &OperationRecord) -> Result<(), OperationError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| OperationError::Unavailable(error.to_string()))?;
        self.kv
            .put(
                &record_key(&record.operation_id),
                Bytes::from(bytes),
                Some(self.retention(record)),
            )
            .await
            .map_err(|error| OperationError::Unavailable(error.to_string()))
    }

    /// How long `record` is kept from now: a `proposed` one until it can be
    /// confirmed no more and then as long as a final one, an `in_progress`
    /// one at least 30 days.
    fn retention(&self, record: &OperationRecord) -> Duration {
        let retain = Duration::from_secs(self.config.retain_final_secs);
        match record.state {
            OperationState::Proposed => {
                let until_expiry = (record.expires_at - Utc::now())
                    .to_std()
                    .unwrap_or_default();
                until_expiry + retain
            }
            OperationState::InProgress => retain.max(MIN_IN_PROGRESS_RETENTION),
            _ => retain,
        }
    }

    async fn get_text(&self, key: &str) -> Result<Option<String>, OperationError> {
        let entry = self
            .kv
            .get(key)
            .await
            .map_err(|error| OperationError::Unavailable(error.to_string()))?;
        Ok(entry.and_then(|entry| String::from_utf8(entry.bytes.to_vec()).ok()))
    }

    async fn acquire(&self, id: &str) -> Result<Lease, OperationError> {
        let key = format!("{RECORD_PREFIX}{id}:lock");
        let token = uuid::Uuid::new_v4().to_string();
        let deadline = tokio::time::Instant::now() + LOCK_WAIT;
        loop {
            let taken = self
                .kv
                .put_if_absent(&key, Bytes::from(token.clone()), Some(LOCK_TTL))
                .await
                .map_err(|error| OperationError::Unavailable(error.to_string()))?;
            if taken {
                return Ok(Lease { key, token });
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(OperationError::Unavailable(
                    "the operation is busy; retry".to_owned(),
                ));
            }
            tokio::time::sleep(LOCK_RETRY).await;
        }
    }

    /// Give `lease` back, unless it lapsed and another took it.
    async fn release(&self, lease: Lease) {
        if let Ok(Some(entry)) = self.kv.get(&lease.key).await
            && entry.bytes.as_ref() == lease.token.as_bytes()
        {
            let _ = self.kv.delete(&lease.key).await;
        }
    }
}

fn record_key(id: &str) -> String {
    format!("{RECORD_PREFIX}{id}")
}

fn run_key(id: &str) -> String {
    format!("{RECORD_PREFIX}{id}:run")
}

/// The key of the operation an action key names, for `owner` and `tool`.
fn action_index_key(owner: &Owner, tool: &str, key: &str) -> String {
    let digest = blake3::hash(format!("{}\u{1f}{tool}\u{1f}{key}", owner.scope()).as_bytes());
    format!("{ACTION_PREFIX}{}", digest.to_hex())
}

/// The text content of a tool result, joined, or `fallback`.
pub fn result_text(result: &Value, fallback: &str) -> String {
    let text: Vec<&str> = result
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    if text.is_empty() {
        fallback.to_owned()
    } else {
        text.join("\n")
    }
}

#[cfg(test)]
#[path = "personal_agent_operations_tests.rs"]
mod tests;
