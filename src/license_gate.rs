//! License gate at boot and reload.
//!
//! Every gateway gates, itself, the entitlement-gated plugins in `plugins[]`
//! and the feature-gated surfaces of its embedded authorization server
//! (interactive sign-in: `sso.interactive_login`; DPoP: `oauth.dpop`; rich
//! authorization requests: `oauth.rich_authorization`) against one licence:
//!
//! - when mcpg.cloud delivers it over the CP channel, the platform's licence:
//!   a cloud licence, verified against the `cloud` keys and issued to the org
//!   the control plane enrolled this gateway into. A delivery is mcpg.cloud's
//!   only when its delivery proof, signed by a `platform` key, names the nonce
//!   this process sent when it opened that Channel and the instance uid of
//!   this gateway's own instance token; a cloud licence counts on no other
//!   delivery, so a control plane without a platform key cannot make one
//!   count. That uid is whatever the enrolling control plane put in the
//!   token, so one that holds a real hybrid enrollment can still pass its
//!   Channel to several gateways in turns. One read back from the state
//!   directory at a restart counts only with the proof kept with it, for a
//!   day after that proof was signed, and until a control plane's own word
//!   replaces it. The config's `license:` block is ignored
//!   then, so a config never chooses its own licence on a gateway mcpg.cloud
//!   licenses;
//! - otherwise its own `license:` block: a self-host licence, verified against
//!   the `self_host` issuer keys compiled into the binary, or the
//!   non-production declaration, also on a gateway a customer's own control
//!   plane runs;
//! - otherwise what that control plane relays: a self-host licence;
//! - otherwise the built-in community tier.
//!
//! No key from configuration is trusted. `license.non_production_use` loads
//! everything under the licence's free non-production grant, loudly.
//!
//! A configured item the gateway's own licence does not entitle refuses the
//! boot or the reload. An item that waits on a licence — an attached gateway's
//! licence not delivered yet or not verifying, a plan the platform's licence
//! does not include, or a licence past its grace period — holds a booting
//! attached gateway for up to [`LICENSE_WAIT`] while a delivery may still
//! cover it. It is then withheld where running without it fails closed: a
//! backend, credential issuer or secret provider simply is not loaded (a
//! binding of a withheld backend fails at call time), and a withheld tool gate
//! refuses every tool call, prompt, resource read and completion in its place,
//! since any of them may be one it judges. Every other
//! waiting item (cluster coordinators, policy
//! engines, identity providers, audit sinks, authorization-server surfaces)
//! holds the boot, because running without it would weaken coordination,
//! authorization, authentication or audit.
//!
//! A standalone gateway keeps what it already loaded across reloads; a restart
//! evaluates everything afresh. An attached gateway is gated again on every
//! delivery, because a delivery is the platform's current word on the org's
//! plan: what it no longer covers is withheld as at boot, and an item that
//! cannot be withheld stays loaded but is held — the gateway refuses every
//! tool call, prompt, resource read and completion, as a held boot serves
//! nothing — until a delivery covers it again. It is gated again, too, when
//! the delivered licence's grace ends, since no delivery need come then. A
//! delivered licence that does not verify says nothing about the plan, so it
//! never replaces one that does. A plugin set the control plane binds that
//! leaves out a gated plugin the gateway loaded, or already withholds, takes
//! it back the same way, so such a set never keeps a lower licence from
//! applying. The licence status is published once the gateway runs on the
//! outcome.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use arc_swap::{ArcSwap, ArcSwapOption};
use chrono::{DateTime, Utc};
use mcpg_control_plane_license::license::{
    self, AUDIENCE_GATEWAY, AUDIENCE_GATEWAY_MANAGED, FEATURE_DPOP, FEATURE_EVENTS_WEBHOOKS,
    FEATURE_INTERACTIVE_LOGIN, FEATURE_RICH_AUTHORIZATION, IssuerRole, LicenseClaims, LicenseError,
    LicenseTerm, TrustPolicy, VendorLicense, is_entitlement_gated, plugin_load_violation,
    verify_vendor_license,
};

use crate::config::{AppConfig, LicenseConfig, SecretsSource};

/// How long a booting gateway waits for the control plane to deliver the
/// licence an item it cannot withhold needs.
pub(crate) const LICENSE_WAIT: Duration = Duration::from_secs(20);

/// The config path of the embedded authorization server, which the
/// sign-in and token surfaces live under.
const SERVER: &str = "governance.access.authorization_server";

/// The licensed surface of MCP Events webhook delivery.
pub const EVENTS_WEBHOOK_SURFACE: &str = "mcp.configurations.events.webhook";

/// The config surfaces a license feature withholds, as
/// `(feature, config path of the block)`. A block counts only when it turns
/// its surface on: `dpop` with `enabled: true`, `authorization_details` with
/// at least one type. A present block that leaves it off needs no feature.
pub fn licensed_config_surfaces(config: &AppConfig) -> Vec<(&'static str, String)> {
    let mut surfaces: Vec<(&'static str, String)> = Vec::new();
    let events = &config.mcp.configurations.events;
    if events.enabled && events.webhook.enabled {
        surfaces.push((FEATURE_EVENTS_WEBHOOKS, EVENTS_WEBHOOK_SURFACE.to_owned()));
    }
    let Some(ref server) = config.governance.access.authorization_server else {
        return surfaces;
    };
    surfaces.extend(
        server
            .trusted_idps
            .iter()
            .filter(|idp| idp.login.is_some())
            .map(|idp| {
                (
                    FEATURE_INTERACTIVE_LOGIN,
                    format!("{SERVER}.trusted_idps[`{}`].login", idp.issuer),
                )
            }),
    );
    if server.interactive.is_some() {
        surfaces.push((FEATURE_INTERACTIVE_LOGIN, format!("{SERVER}.interactive")));
    }
    if server.dpop.enabled {
        surfaces.push((FEATURE_DPOP, format!("{SERVER}.dpop")));
    }
    if server.authorization_details.enabled() {
        surfaces.push((
            FEATURE_RICH_AUTHORIZATION,
            format!("{SERVER}.authorization_details"),
        ));
    }
    surfaces
}

/// What the control plane has told this gateway about its licence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Delivery {
    /// Not attached to a control plane.
    #[default]
    Standalone,
    /// Attached; the control plane has delivered nothing yet.
    Pending,
    /// The control plane's latest word: the org's licence (empty when the org
    /// holds none) and the org it enrolled this gateway into.
    Delivered {
        license_jwt: String,
        org_slug: String,
        origin: Origin,
        /// The control plane reports that its refresh of this licence is
        /// failing.
        refresh_failing: bool,
    },
}

impl Delivery {
    /// A delivery on a Channel of this process, as the control plane sent it.
    pub fn received(license_jwt: String, org_slug: String, origin: Origin) -> Self {
        Delivery::Delivered {
            license_jwt,
            org_slug,
            origin,
            refresh_failing: false,
        }
    }

    fn origin(&self) -> Option<Origin> {
        match self {
            Delivery::Delivered { origin, .. } => Some(*origin),
            _ => None,
        }
    }
}

/// How the gateway came by a delivered licence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// mcpg.cloud delivered it on a Channel of this process: its delivery
    /// proof verified. With [`Origin::CachedProven`] while that holds, the
    /// only origin under which a cloud licence counts and the gateway's own
    /// `license:` block is ignored.
    Proven,
    /// A control plane delivered it on a Channel of this process with no
    /// proof that verifies: a customer's own control plane.
    Unproven,
    /// Delivered before this process started and read back from the state
    /// directory with no proof that still holds, so it proves nothing about
    /// where it came from.
    Cached,
    /// Delivered before this process started and read back from the state
    /// directory with the proof mcpg.cloud sent it with, which verified
    /// again. It counts as [`Origin::Proven`] until `until` (unix seconds),
    /// a day after the proof was signed, unless a control plane's own word
    /// replaces it first.
    CachedProven { until: i64 },
}

impl Origin {
    /// What this origin counts as at `now`: a cached proven delivery counts as
    /// proven until its window ends, and as cached after.
    fn at(self, now: i64) -> Origin {
        match self {
            Origin::CachedProven { until } if now < until => Origin::Proven,
            Origin::CachedProven { .. } => Origin::Cached,
            origin => origin,
        }
    }

    fn is_cached(self) -> bool {
        matches!(self, Origin::Cached | Origin::CachedProven { .. })
    }
}

/// Everything the gate reads besides the config.
pub(crate) struct GateInputs<'a> {
    pub delivery: &'a Delivery,
    /// The plugin ids the control plane bound to this gateway, when it bound a
    /// plugin set. A gated plugin outside it is refused.
    pub bound_plugins: Option<&'a BTreeSet<String>>,
    /// Gated items the running gateway already loaded ([`GateOutcome::admitted`]
    /// of the last boot or reload). Empty at boot.
    pub admitted: &'a BTreeSet<String>,
    /// Gated plugins the running gateway withholds ([`GateOutcome::withheld`]
    /// of the last boot or reload). Empty at boot.
    pub withheld: &'a [String],
    /// The boot of an attached gateway that started with what the control
    /// plane delivered to the process before it ([`platform::restarted`]).
    /// What the delivery or the bound set no longer covers is taken back as
    /// on the running gateway (withheld, or loaded and held) rather than
    /// refusing the boot, so a restart never crash-loops on what the gateway
    /// before it was already holding.
    pub restart: bool,
    /// Unix seconds.
    pub now: i64,
}

/// Why an item waits on a licence instead of being refused as a config error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HoldReason {
    /// Attached, and the control plane has not delivered a licence.
    Pending,
    /// The licence the control plane delivered does not verify.
    Unverified(String),
    /// The platform's licence for the org does not include it.
    NotInPlan(String),
    /// The licence expired at `expired` (unix seconds) and its grace of
    /// `grace_days` ended.
    Lapsed { expired: i64, grace_days: i64 },
    /// The plugin set the control plane bound to this gateway leaves them
    /// out.
    NotBound,
    /// The licence's reason, and the bound plugin set leaves some of them
    /// out too.
    AndNotBound(Box<HoldReason>),
}

impl HoldReason {
    /// Whether a later delivery can change the answer, so a booting gateway
    /// waits for one.
    fn may_resolve_by_delivery(&self) -> bool {
        matches!(self, HoldReason::Pending | HoldReason::Unverified(_))
    }

    /// Whether what keeps the items out is a delivery or a bound set read
    /// back at start, which the control plane's own word may replace.
    fn rests_on_cache(&self, delivery_cached: bool, bound_cached: bool) -> bool {
        match self {
            HoldReason::NotBound => bound_cached,
            HoldReason::AndNotBound(_) => delivery_cached || bound_cached,
            _ => delivery_cached,
        }
    }

    fn describe(&self) -> String {
        match self {
            HoldReason::Pending => {
                "the control plane has not delivered this gateway's licence".to_owned()
            }
            HoldReason::Unverified(e) => {
                format!("the licence the control plane delivered does not verify: {e}")
            }
            HoldReason::NotInPlan(plan) => {
                format!("the org's `{plan}` licence does not include them")
            }
            HoldReason::Lapsed {
                expired,
                grace_days,
            } => format!(
                "the licence expired on {} and its {grace_days}-day grace period ended on {}",
                day(*expired),
                day(license::grace_ends_after(*expired, *grace_days))
            ),
            HoldReason::NotBound => {
                "the plugin set the control plane bound to this gateway leaves them out".to_owned()
            }
            HoldReason::AndNotBound(licence) => format!(
                "{}; the plugin set the control plane bound to this gateway leaves some of them \
                 out",
                licence.describe()
            ),
        }
    }
}

/// How a gated plugin can wait for a licence, by what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitShape {
    /// Its absence fails closed: whatever uses it errors.
    Withhold,
    /// A tool gate: withheld, and every tool call is refused in its place.
    WithholdAndHoldTools,
    /// Running without it would weaken the gateway; it holds the boot.
    MustWait,
}

/// Decided from the gated plugin id rather than the entry's declared class:
/// the gated plugins are first-party and their classes are known.
fn wait_shape(plugin_id: &str) -> WaitShape {
    let id = plugin_id
        .strip_prefix(license::FIRST_PARTY_ID_PREFIX)
        .unwrap_or(plugin_id);
    let under = |ns: &str| id.starts_with(ns);
    if under("payment.")
        || under("tool-gate.")
        || id == "tool-gate-slack-approval"
        || id == "guardrails"
    {
        WaitShape::WithholdAndHoldTools
    } else if under("backend.") || under("credential.") || under("secret.") {
        WaitShape::Withhold
    } else {
        WaitShape::MustWait
    }
}

/// Where the licence the gateway runs under came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseSource {
    /// The gateway's own `license:` block.
    LicenseBlock,
    /// Delivered by the control plane.
    Platform,
    /// No licence: the built-in community tier.
    Community,
    /// `license.non_production_use: true`.
    NonProductionDeclaration,
}

impl LicenseSource {
    fn as_str(self) -> &'static str {
        match self {
            LicenseSource::LicenseBlock => "license_block",
            LicenseSource::Platform => "platform",
            LicenseSource::Community => "community",
            LicenseSource::NonProductionDeclaration => "non_production_declaration",
        }
    }
}

/// The licence this gateway runs under, for the admin health endpoint, the
/// boot log and the `mcpg_license_*` metrics.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LicenseStatus {
    pub plan: String,
    pub source: LicenseSource,
    /// `current`, `expiring` (a self-host licence within 30 days of expiry;
    /// an mcpg.cloud licence, which the platform renews before it expires,
    /// only while the control plane reports its refresh failing), `grace`
    /// (expired, within the grace period), `lapsed`, `pending` (waiting for
    /// the control plane), or `unlicensed` (community, or the non-production
    /// grant).
    pub state: &'static str,
    /// The control plane reports that its refresh of the delivered licence
    /// is failing.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub refresh_failing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_ends_at: Option<DateTime<Utc>>,
    /// Non-production use only: `license.non_production_use`, or a licence
    /// that marks it.
    pub non_production: bool,
    /// Gated plugins not loaded until a licence covers them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<String>,
    /// Loaded items the delivered licence no longer covers and the gateway
    /// cannot run without: while any is held, the gateway refuses every tool
    /// call, prompt, resource read and completion.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<String>,
}

/// One withheld plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub plugin_id: String,
    pub holds_tools: bool,
}

/// A config the gate admits, possibly with plugins withheld.
#[derive(Clone, Debug)]
pub(crate) struct GateOutcome {
    pub status: LicenseStatus,
    /// Every gated item loaded (`plugin:<id>`, `surface:<path>`); the next
    /// reload of a standalone gateway keeps them.
    pub admitted: BTreeSet<String>,
    pub withheld: Vec<Withheld>,
    /// Loaded gated plugins (by id) and surfaces (by config path) the
    /// licence no longer covers and that cannot be withheld.
    pub held: Vec<String>,
    /// Why withheld or held items wait; set whenever either is not empty.
    pub hold: Option<HoldReason>,
    /// [`platform::generation`] when the delivery and bound set this outcome
    /// rests on were read.
    pub platform_generation: u64,
    /// Whether it gated an attached gateway.
    pub attached: bool,
    /// When the cached licence mcpg.cloud last proved, which this outcome
    /// counts, stops counting (unix seconds).
    pub counts_until: Option<i64>,
}

impl GateOutcome {
    /// Why MCP Events webhook delivery stops while its surface is held: an
    /// attached gateway whose delivered licence no longer covers it.
    pub fn events_hold(&self) -> Option<String> {
        if !self.held.iter().any(|item| item == EVENTS_WEBHOOK_SURFACE) {
            return None;
        }
        let why = self
            .hold
            .as_ref()
            .map(HoldReason::describe)
            .unwrap_or_default();
        Some(format!(
            "MCP Events webhook delivery is held until a licence covers {EVENTS_WEBHOOK_SURFACE}: {why}"
        ))
    }

    /// The refusal every OAuth endpoint of the embedded authorization server
    /// answers with while one of its surfaces is held.
    pub fn authorization_server_hold(&self) -> Option<String> {
        let surfaces: Vec<&str> = self
            .held
            .iter()
            .map(String::as_str)
            .filter(|item| item.starts_with(SERVER))
            .collect();
        if surfaces.is_empty() {
            return None;
        }
        let why = self
            .hold
            .as_ref()
            .map(HoldReason::describe)
            .unwrap_or_default();
        Some(format!(
            "the authorization server is unavailable until a licence covers {}: {why}",
            surfaces.join(", ")
        ))
    }

    /// The refusal a tool call, prompt, resource read or completion gets
    /// while a withheld tool gate or a held item waits.
    pub fn tool_hold(&self) -> Option<String> {
        let gates: Vec<&str> = self
            .withheld
            .iter()
            .filter(|w| w.holds_tools)
            .map(|w| w.plugin_id.as_str())
            .collect();
        let mut waiting = Vec::new();
        if !gates.is_empty() {
            waiting.push(format!("the tool gate(s) {}", gates.join(", ")));
        }
        if !self.held.is_empty() {
            waiting.push(format!(
                "{}, which this gateway cannot run without",
                self.held.join(", ")
            ));
        }
        if waiting.is_empty() {
            return None;
        }
        let why = self
            .hold
            .as_ref()
            .map(HoldReason::describe)
            .unwrap_or_default();
        Some(format!(
            "tool calls, prompts, resource reads and completions are refused until a licence \
             covers {}: {why}",
            waiting.join(" and ")
        ))
    }
}

/// A config the gate does not admit.
#[derive(Debug)]
pub(crate) struct GateRefusal {
    plan: String,
    /// Items the licence does not entitle: a config error.
    refused: Vec<String>,
    /// Items that cannot be withheld and wait on a licence.
    awaiting: Vec<String>,
    hold: Option<HoldReason>,
}

impl GateRefusal {
    fn waits_for_delivery(&self) -> bool {
        self.refused.is_empty()
            && self
                .hold
                .as_ref()
                .is_some_and(HoldReason::may_resolve_by_delivery)
    }
}

impl std::fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.refused.is_empty() {
            write!(
                f,
                "license gate: plan `{}` does not license {} configured item(s):\n  - {}\n\
                 Install an entitling MCPG licence (`license.token` / `license.token_file`), \
                 declare a non-production deployment (`license.non_production_use: true`), \
                 or remove them. Licensing: https://mcpg.dev/license",
                self.plan,
                self.refused.len(),
                self.refused.join("\n  - "),
            )?;
            if !self.awaiting.is_empty() {
                f.write_str("\n")?;
            }
        }
        if !self.awaiting.is_empty() {
            write!(
                f,
                "license gate: {} configured item(s) wait for a licence, because {}:\n  - {}\n\
                 They cannot be left out while the gateway runs: that would weaken \
                 coordination, authorization, authentication or audit.",
                self.awaiting.len(),
                self.hold
                    .as_ref()
                    .map(HoldReason::describe)
                    .unwrap_or_default(),
                self.awaiting.join("\n  - "),
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for GateRefusal {}

/// The licence resolved for one evaluation.
struct Resolved {
    /// What gated items are checked against: the licence's claims, or the
    /// community tier when there is none or it grants nothing any more.
    claims: LicenseClaims,
    status: LicenseStatus,
    /// Set when items the claims do not cover wait instead of being refused.
    hold: Option<HoldReason>,
}

/// Standalone check: refuses any gated item or surface the gateway's own
/// licence (or the community tier) does not admit, and anything that would
/// have to wait. Tests and callers without a control plane use this.
pub fn enforce_license_gate(config: &AppConfig) -> anyhow::Result<()> {
    let outcome = evaluate(
        config,
        &GateInputs {
            delivery: &Delivery::Standalone,
            bound_plugins: None,
            admitted: &BTreeSet::new(),
            withheld: &[],
            restart: false,
            now: Utc::now().timestamp(),
        },
    )?;
    if !outcome.withheld.is_empty() {
        anyhow::bail!(
            "license gate: withholding {}: {}",
            outcome
                .withheld
                .iter()
                .map(|w| w.plugin_id.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            outcome
                .hold
                .as_ref()
                .map(HoldReason::describe)
                .unwrap_or_default()
        );
    }
    Ok(())
}

fn plugin_key(id: &str) -> String {
    format!("plugin:{id}")
}

pub(crate) fn surface_key(path: &str) -> String {
    format!("surface:{path}")
}

/// Decide what `config` may load. `Err` refuses it; `Ok` may still withhold
/// plugins, which [`withhold`] then removes from the config.
pub(crate) fn evaluate(
    config: &AppConfig,
    inputs: &GateInputs<'_>,
) -> Result<GateOutcome, GateRefusal> {
    // Gate on the artifact's manifest id (`ref`), not the operator alias: the
    // loader refuses a cdylib whose own manifest id is not `ref`. A disabled
    // entry is never loaded.
    let entries: Vec<&str> = config
        .plugins
        .iter()
        .filter(|entry| !entry.disabled)
        .map(|entry| entry.r#ref.as_deref().unwrap_or(entry.id.as_str()))
        .collect();
    let gated: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|id| is_entitlement_gated(id))
        .collect();
    let surfaces = licensed_config_surfaces(config);

    // The bound set is the control plane's entitlement decision, so it
    // governs the gated plugins only. The free plugins and the coordinator the
    // platform adds to a multi-replica gateway are in no tenant's set, and
    // the platform renders them into every managed gateway's config.
    let outside_bound_set = |id: &str| {
        inputs
            .bound_plugins
            .is_some_and(|bound| id != license::PLATFORM_COORDINATOR_PLUGIN && !bound.contains(id))
    };

    let resolved = match resolve(config, inputs) {
        Ok(resolved) => resolved,
        Err(e) if gated.is_empty() && surfaces.is_empty() => {
            // Nothing here needs the licence, so a broken one costs nothing
            // yet; it is reported, and refuses the first config that needs it.
            tracing::warn!(error = %format!("{e:#}"), "license: the configured licence does not verify");
            Resolved {
                claims: LicenseClaims::community(AUDIENCE_GATEWAY),
                status: community_status(),
                hold: None,
            }
        }
        Err(e) => {
            return Err(GateRefusal {
                plan: "unresolved".into(),
                refused: vec![format!("{e:#}")],
                awaiting: Vec::new(),
                hold: None,
            });
        }
    };

    // A standalone gateway keeps what it loaded until it restarts, so a
    // reload for an unrelated change never fails on its own licence. An
    // attached gateway's delivery is the platform's current word on the
    // org's plan, so what it loaded is judged again against each one.
    let keeps_loaded = matches!(inputs.delivery, Delivery::Standalone);
    let mut admitted = BTreeSet::new();
    let mut withheld = Vec::new();
    let mut held = Vec::new();
    let mut refused = Vec::new();
    let mut awaiting = Vec::new();
    let (mut licence_waits, mut bound_waits) = (false, false);
    // What a running gateway cannot keep: withheld when it can run without
    // it, else left loaded and held.
    let mut take_back = |id: &str, key: String, admitted: &mut BTreeSet<String>| {
        let shape = wait_shape(id);
        if shape == WaitShape::MustWait {
            admitted.insert(key);
            held.push(id.to_owned());
        } else {
            withheld.push(Withheld {
                plugin_id: id.to_owned(),
                holds_tools: shape == WaitShape::WithholdAndHoldTools,
            });
        }
    };

    for id in &gated {
        let key = plugin_key(id);
        let loaded = inputs.admitted.contains(&key);
        if outside_bound_set(id) {
            // A running attached gateway applies a bound set that leaves out
            // what it loaded, or what it already withholds, as it applies a
            // lower licence, so a set that leaves one out never stops a lower
            // licence from applying. A restart lands where the running
            // gateway was, so one the set took back stays taken back. A
            // config that adds one is refused.
            let ran = loaded || inputs.withheld.iter().any(|w| w == id);
            if (ran || inputs.restart) && !keeps_loaded {
                bound_waits = true;
                take_back(id, key, &mut admitted);
            } else {
                refused.push(format!(
                    "plugin `{id}` is not in the plugin set the control plane bound to this \
                     gateway"
                ));
            }
            continue;
        }
        let Some(violation) = plugin_load_violation(&resolved.claims, id) else {
            admitted.insert(key);
            continue;
        };
        if (loaded && keeps_loaded) || license::admits_platform_coordinator(&resolved.claims, id) {
            admitted.insert(key);
            continue;
        }
        match (&resolved.hold, wait_shape(id)) {
            (None, _) => refused.push(violation.to_string()),
            (Some(_), WaitShape::MustWait) if !loaded && !inputs.restart => {
                awaiting.push(violation.to_string())
            }
            (Some(_), _) => {
                licence_waits = true;
                take_back(id, key, &mut admitted);
            }
        }
    }
    for (feature, path) in &surfaces {
        let key = surface_key(path);
        let loaded = inputs.admitted.contains(&key);
        if resolved.claims.has_feature(feature) || (loaded && keeps_loaded) {
            admitted.insert(key);
            continue;
        }
        let item = format!(
            "{path} requires the `{feature}` plan feature, which this license does not grant"
        );
        match &resolved.hold {
            Some(_) if loaded || inputs.restart => {
                licence_waits = true;
                admitted.insert(key);
                held.push(path.clone());
            }
            Some(_) => awaiting.push(item),
            None => refused.push(item),
        }
    }

    if !refused.is_empty() || !awaiting.is_empty() {
        return Err(GateRefusal {
            plan: resolved.claims.plan.clone(),
            refused,
            awaiting,
            hold: resolved.hold,
        });
    }
    let mut status = resolved.status;
    status.withheld = withheld.iter().map(|w| w.plugin_id.clone()).collect();
    status.held = held.clone();
    let hold = match (
        licence_waits.then_some(resolved.hold).flatten(),
        bound_waits,
    ) {
        (Some(licence), true) => Some(HoldReason::AndNotBound(Box::new(licence))),
        (licence, false) => licence,
        (None, true) => Some(HoldReason::NotBound),
    };
    let counts_until = match inputs.delivery {
        Delivery::Delivered {
            origin: Origin::CachedProven { until },
            ..
        } if inputs.now < *until && status.source == LicenseSource::Platform => Some(*until),
        _ => None,
    };
    Ok(GateOutcome {
        status,
        admitted,
        withheld,
        held,
        hold,
        platform_generation: 0,
        attached: !matches!(inputs.delivery, Delivery::Standalone),
        counts_until,
    })
}

/// Take withheld plugins out of `config`: they are left in `plugins[]`,
/// disabled, so nothing loads them and anything naming them fails where the
/// name is resolved.
pub(crate) fn withhold(config: &mut AppConfig, outcome: &GateOutcome) {
    for entry in &mut config.plugins {
        let id = entry.r#ref.as_deref().unwrap_or(entry.id.as_str());
        if outcome.withheld.iter().any(|w| w.plugin_id == id) {
            entry.disabled = true;
        }
    }
}

/// The binding kinds the withheld backend plugins serve. Every gated backend
/// is first-party, and `dev.mcpg.backend.<kind>` serves `kind: <kind>`.
pub(crate) fn withheld_backend_kinds(outcome: &GateOutcome) -> BTreeSet<String> {
    outcome
        .withheld
        .iter()
        .filter_map(|w| {
            w.plugin_id
                .strip_prefix(license::FIRST_PARTY_ID_PREFIX)
                .unwrap_or(&w.plugin_id)
                .strip_prefix("backend.")
                .map(str::to_owned)
        })
        .collect()
}

fn community_status() -> LicenseStatus {
    LicenseStatus {
        plan: "community".into(),
        source: LicenseSource::Community,
        state: "unlicensed",
        refresh_failing: false,
        expires_at: None,
        grace_ends_at: None,
        non_production: false,
        withheld: Vec::new(),
        held: Vec::new(),
    }
}

fn timestamp(secs: i64) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(secs, 0)
}

/// `secs` as a calendar day (UTC).
fn day(secs: i64) -> String {
    timestamp(secs)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| secs.to_string())
}

/// Status and gating claims of a verified licence at `now`. The grace past
/// `exp` follows the key that signed it: a cloud licence's is the platform's
/// refresh-failure grace, a self-host licence's the self-host one.
///
/// A cloud licence is re-issued before it expires, and its `exp` is never
/// more than a few days past the end of the billing month, so the 30-day
/// warning would hold for most of every month. It is `expiring` only while
/// the control plane reports its refresh failing (`refresh_failing`), which
/// is when it may run out.
fn resolved_from(
    verified: VendorLicense,
    source: LicenseSource,
    refresh_failing: bool,
    now: i64,
) -> Resolved {
    let grace_days = license::expiry_grace_days(verified.role);
    let exp = verified.claims.exp;
    let term = LicenseTerm::with_grace(exp, now, grace_days);
    let state = match term {
        LicenseTerm::Current | LicenseTerm::ExpiringSoon if verified.role == IssuerRole::Cloud => {
            if refresh_failing {
                LicenseTerm::ExpiringSoon.as_str()
            } else {
                LicenseTerm::Current.as_str()
            }
        }
        term => term.as_str(),
    };
    let status = LicenseStatus {
        plan: verified.claims.plan.clone(),
        source,
        state,
        refresh_failing,
        expires_at: timestamp(exp),
        grace_ends_at: timestamp(license::grace_ends_after(exp, grace_days)),
        non_production: verified.claims.non_production,
        withheld: Vec::new(),
        held: Vec::new(),
    };
    if term == LicenseTerm::Lapsed {
        return Resolved {
            claims: LicenseClaims::community(AUDIENCE_GATEWAY),
            status,
            hold: Some(HoldReason::Lapsed {
                expired: exp,
                grace_days,
            }),
        };
    }
    let hold = (source == LicenseSource::Platform)
        .then(|| HoldReason::NotInPlan(verified.claims.plan.clone()));
    Resolved {
        claims: verified.claims,
        status,
        hold,
    }
}

fn resolve(config: &AppConfig, inputs: &GateInputs<'_>) -> anyhow::Result<Resolved> {
    let has_block = config.license != LicenseConfig::default();
    match inputs.delivery.origin().map(|o| o.at(inputs.now)) {
        Some(Origin::Proven) => {
            if has_block {
                tracing::warn!(
                    "license: mcpg.cloud delivers this gateway's licence; its `license:` block \
                     (token, token_file, non_production_use) is ignored"
                );
            }
            return Ok(resolve_delivery(inputs));
        }
        // No proven mcpg.cloud delivery: a customer's own control plane, or
        // none has answered this process yet. The gateway's own block counts.
        _ if !has_block && !matches!(inputs.delivery, Delivery::Standalone) => {
            return Ok(resolve_delivery(inputs));
        }
        _ => {}
    }
    // Until the control plane's word to this process shows it is not
    // mcpg.cloud, a proven delivery may still set the block aside, so what the
    // block does not cover waits for that delivery instead of being refused.
    let awaiting = awaits_proven_delivery(inputs);
    match resolve_block(config, inputs.now) {
        Ok(Some(resolved)) => Ok(Resolved {
            hold: awaiting.or(resolved.hold),
            ..resolved
        }),
        Ok(None) => Ok(resolve_delivery(inputs)),
        Err(e) if awaiting.is_some() => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "license: this gateway's `license:` block does not verify; what needs a licence \
                 waits for the control plane's delivery"
            );
            Ok(Resolved {
                claims: LicenseClaims::community(AUDIENCE_GATEWAY),
                status: LicenseStatus {
                    state: "pending",
                    ..community_status()
                },
                hold: awaiting,
            })
        }
        Err(e) => Err(e),
    }
}

/// Why an attached gateway that runs on its own `license:` block may still be
/// licensed by a delivery mcpg.cloud proves: no word from the control plane to
/// this process yet (a delivery read back at start is none), or a cloud
/// licence sent without a proof that verifies. `None` once the control
/// plane's word is a customer control plane's: a self-host licence or none.
fn awaits_proven_delivery(inputs: &GateInputs<'_>) -> Option<HoldReason> {
    match (
        inputs.delivery,
        inputs.delivery.origin().map(|o| o.at(inputs.now)),
    ) {
        (Delivery::Pending, _) | (_, Some(Origin::Cached)) => Some(HoldReason::Pending),
        (_, Some(Origin::Unproven)) => resolve_delivery(inputs)
            .hold
            .filter(HoldReason::may_resolve_by_delivery),
        _ => None,
    }
}

/// The licence of the gateway's own `license:` block, when it sets one.
fn resolve_block(config: &AppConfig, now: i64) -> anyhow::Result<Option<Resolved>> {
    if config.license.non_production_use {
        let mut claims = LicenseClaims::community(AUDIENCE_GATEWAY);
        claims.plugin_entitlements = vec!["*".into()];
        claims.features = license::features_for("enterprise");
        claims.plan = "non-production".into();
        return Ok(Some(Resolved {
            claims,
            status: LicenseStatus {
                plan: "non-production".into(),
                source: LicenseSource::NonProductionDeclaration,
                state: "unlicensed",
                refresh_failing: false,
                expires_at: None,
                grace_ends_at: None,
                non_production: true,
                withheld: Vec::new(),
                held: Vec::new(),
            },
            hold: None,
        }));
    }
    Ok(verify_license_block(config)?
        .map(|verified| resolved_from(verified, LicenseSource::LicenseBlock, false, now)))
}

/// The licence of an attached gateway: what the control plane delivered.
fn resolve_delivery(inputs: &GateInputs<'_>) -> Resolved {
    match inputs.delivery {
        Delivery::Standalone => Resolved {
            claims: LicenseClaims::community(AUDIENCE_GATEWAY),
            status: community_status(),
            hold: None,
        },
        Delivery::Pending => Resolved {
            claims: LicenseClaims::community(AUDIENCE_GATEWAY),
            status: LicenseStatus {
                state: "pending",
                ..community_status()
            },
            hold: Some(HoldReason::Pending),
        },
        Delivery::Delivered { license_jwt, .. } if license_jwt.trim().is_empty() => Resolved {
            claims: LicenseClaims::community(AUDIENCE_GATEWAY),
            status: LicenseStatus {
                source: LicenseSource::Platform,
                ..community_status()
            },
            hold: Some(HoldReason::NotInPlan("community".into())),
        },
        Delivery::Delivered {
            license_jwt,
            org_slug,
            origin,
            refresh_failing,
        } => match verify_delivered(license_jwt.trim(), org_slug, origin.at(inputs.now)) {
            Ok(verified) => resolved_from(
                verified,
                LicenseSource::Platform,
                *refresh_failing,
                inputs.now,
            ),
            Err(e) => Resolved {
                claims: LicenseClaims::community(AUDIENCE_GATEWAY),
                status: LicenseStatus {
                    source: LicenseSource::Platform,
                    state: "pending",
                    ..community_status()
                },
                hold: Some(HoldReason::Unverified(e)),
            },
        },
    }
}

/// A licence the control plane delivered: a cloud licence issued to the org it
/// enrolled this gateway into, which counts only on a delivery mcpg.cloud
/// proved, or a self-host licence a customer's own control plane relays.
fn verify_delivered(token: &str, org_slug: &str, origin: Origin) -> Result<VendorLicense, String> {
    let cloud = TrustPolicy {
        audience: AUDIENCE_GATEWAY_MANAGED,
        roles: &[IssuerRole::Cloud],
        enforce_expiry: false,
    };
    match verify_vendor_license(token, &cloud) {
        Ok(verified) if verified.claims.tenant_slug != org_slug => Err(format!(
            "it is issued to `{}`, not to `{org_slug}`, the org this gateway is enrolled into",
            verified.claims.tenant_slug
        )),
        Ok(verified) if origin == Origin::Proven => Ok(verified),
        Ok(_) if origin.is_cached() => Err(
            "it is an mcpg.cloud licence read back from this gateway's state at start without a \
             proof that still holds; one counts once mcpg.cloud delivers it to this process"
                .to_owned(),
        ),
        Ok(_) => Err(
            "it is an mcpg.cloud licence, and the delivery carries no proof that mcpg.cloud \
             sent it; a cloud licence runs only on a gateway mcpg.cloud delivers it to"
                .to_owned(),
        ),
        Err(LicenseError::IssuerRoleNotAccepted { .. }) => {
            let self_host = TrustPolicy {
                audience: AUDIENCE_GATEWAY,
                roles: &[IssuerRole::SelfHost],
                enforce_expiry: false,
            };
            verify_vendor_license(token, &self_host).map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// What a delivery's proof binds besides the org and the licence: the nonce
/// the Channel it came down opened with, and the instance uid that Channel is
/// authenticated as.
#[cfg(any(feature = "cp-attached", test))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ChannelBinding<'a> {
    pub nonce: &'a str,
    pub instance_uid: &'a str,
}

/// The delivery `proof` must vouch for; `None` when the licence does not
/// verify, which the gate reports on its own.
#[cfg(any(feature = "cp-attached", test))]
fn expected_delivery<'a>(
    license_jwt: &'a str,
    org_slug: &'a str,
    channel: ChannelBinding<'a>,
) -> Option<mcpg_control_plane_license::delivery::ExpectedDelivery<'a>> {
    let license_jwt = license_jwt.trim();
    let license_non_production = if license_jwt.is_empty() {
        false
    } else {
        verify_delivered(license_jwt, org_slug, Origin::Proven)
            .ok()?
            .claims
            .non_production
    };
    Some(mcpg_control_plane_license::delivery::ExpectedDelivery {
        nonce: channel.nonce,
        instance_uid: channel.instance_uid,
        org_slug,
        license_jwt,
        license_non_production,
    })
}

/// Why a delivery's cloud licence counts for nothing, as the gateway reports
/// it to the control plane that sent it. Never the licence.
#[cfg(any(feature = "cp-attached", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeliveryRefusal {
    /// `no_proof` or `proof_refused`.
    pub reason: &'static str,
    /// The `kid` the refused proof's header names, unverified; empty for
    /// `no_proof` or a header that names none.
    pub proof_kid: String,
}

/// A delivery that came down a Channel of this process, judged.
#[cfg(any(feature = "cp-attached", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JudgedDelivery {
    pub origin: Origin,
    /// Set when the delivery carries a cloud licence for this gateway's org
    /// that counts for nothing.
    pub refusal: Option<DeliveryRefusal>,
}

/// Judge a delivery that came down a Channel of this process: its origin is
/// [`Origin::Proven`] when `proof` verifies for that Channel, the org and the
/// licence, else [`Origin::Unproven`]. A cloud licence that arrives unproven
/// counts for nothing, is counted in
/// `mcpg_license_unproven_deliveries_total` by why (`no_proof` or
/// `proof_refused`), and comes back as the refusal the gateway reports.
#[cfg(any(feature = "cp-attached", test))]
pub(crate) fn judge_delivery(
    license_jwt: &str,
    org_slug: &str,
    proof: &str,
    channel: ChannelBinding<'_>,
    now: i64,
) -> JudgedDelivery {
    use mcpg_control_plane_license::delivery::verify_delivery_proof;
    let unproven = |refusal| JudgedDelivery {
        origin: Origin::Unproven,
        refusal,
    };
    if proof.trim().is_empty() {
        return unproven(unproven_cloud_licence(
            license_jwt,
            org_slug,
            "no_proof",
            "",
        ));
    }
    let Some(expected) = expected_delivery(license_jwt, org_slug, channel) else {
        return unproven(None);
    };
    match verify_delivery_proof(proof, &expected, now) {
        Ok(_) => JudgedDelivery {
            origin: Origin::Proven,
            refusal: None,
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                "license: the delivery's proof does not verify, so it is taken as a customer \
                 control plane's: a cloud licence it carries does not count"
            );
            unproven(unproven_cloud_licence(
                license_jwt,
                org_slug,
                "proof_refused",
                proof,
            ))
        }
    }
}

/// Count a delivery that carries a cloud licence for this gateway's org
/// without a proof that verifies: one a customer's control plane relays, or
/// one mcpg.cloud's sent without a proof the gateway accepts. The refusal to
/// report for it; `None` for a delivery that carries no such licence.
#[cfg(any(feature = "cp-attached", test))]
fn unproven_cloud_licence(
    license_jwt: &str,
    org_slug: &str,
    reason: &'static str,
    proof: &str,
) -> Option<DeliveryRefusal> {
    let license_jwt = license_jwt.trim();
    if license_jwt.is_empty()
        || !verify_delivered(license_jwt, org_slug, Origin::Proven)
            .is_ok_and(|verified| verified.role == IssuerRole::Cloud)
    {
        return None;
    }
    metrics::counter!("mcpg_license_unproven_deliveries_total", "reason" => reason).increment(1);
    Some(DeliveryRefusal {
        reason,
        proof_kid: mcpg_control_plane_license::delivery::delivery_proof_kid(proof)
            .unwrap_or_default(),
    })
}

/// The origin of a delivery read back from the state directory at start, with
/// the proof kept with it: [`Origin::CachedProven`] while that proof verifies
/// again for the Channel it was kept with and was signed less than a day ago,
/// else [`Origin::Cached`].
#[cfg(any(feature = "cp-attached", test))]
pub(crate) fn cached_origin_of(
    license_jwt: &str,
    org_slug: &str,
    proof: &str,
    channel: ChannelBinding<'_>,
    now: i64,
) -> Origin {
    use mcpg_control_plane_license::delivery::verify_cached_delivery_proof;
    if proof.trim().is_empty() {
        return Origin::Cached;
    }
    let Some(expected) = expected_delivery(license_jwt, org_slug, channel) else {
        return Origin::Cached;
    };
    match verify_cached_delivery_proof(proof, &expected, now) {
        Ok(until) => Origin::CachedProven { until },
        Err(e) => {
            tracing::info!(
                error = %e,
                "license: the proof kept with the cached licence no longer holds; it waits for \
                 the control plane"
            );
            Origin::Cached
        }
    }
}

/// `license.token` after the config-load substitutions: `${env.X}`, then
/// `${secret.NAME}` from `gateway.secrets.dir`. Errors name the field and the
/// reference, never a value.
fn expand_license_field(
    field: &str,
    raw: Option<&str>,
    secrets: &SecretsSource,
) -> anyhow::Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let expanded = crate::runtime::expr::resolve_env_in_string(raw)
        .and_then(|s| crate::runtime::expr::resolve_secret_in_string(&s, &|n| secrets.lookup(n)))
        .with_context(|| format!("license.{field}"))?;
    Ok(Some(expanded))
}

/// The token of the `license:` block, if one is configured.
fn configured_token(config: &AppConfig) -> anyhow::Result<Option<String>> {
    let cfg: &LicenseConfig = &config.license;
    if cfg
        .pubkey_pem
        .as_deref()
        .is_some_and(|p| !p.trim().is_empty())
    {
        tracing::warn!(
            "license.pubkey_pem is deprecated and ignored: a licence verifies only against the \
             MCPG issuer keys compiled into this build"
        );
    }
    let secrets = SecretsSource::from_config(&config.gateway.secrets);
    let token = expand_license_field("token", cfg.token.as_deref(), &secrets)?;
    let inline = token.as_deref().map(str::trim).filter(|t| !t.is_empty());
    if inline.is_none() && cfg.token.as_deref().is_some_and(|t| !t.trim().is_empty()) {
        anyhow::bail!("license.token is set but resolves to an empty value");
    }
    let file = cfg
        .token_file
        .as_deref()
        .filter(|p| !p.as_os_str().is_empty());
    let token = match (inline, file) {
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "both license.token and license.token_file are set — configure exactly one"
            )
        }
        (Some(t), None) => t.to_owned(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading license.token_file `{}`", path.display()))?
            .trim()
            .to_owned(),
    };
    if token.is_empty() {
        anyhow::bail!("configured license token is empty");
    }
    Ok(Some(token))
}

/// The `license:` block's licence, verified against the self-host issuer
/// keys. Expiry is not checked here; the gate's grace policy judges it. Any
/// other failure refuses: a paying install must not silently degrade.
fn verify_license_block(config: &AppConfig) -> anyhow::Result<Option<VendorLicense>> {
    let Some(token) = configured_token(config)? else {
        return Ok(None);
    };
    let policy = TrustPolicy {
        audience: AUDIENCE_GATEWAY,
        roles: &[IssuerRole::SelfHost],
        enforce_expiry: false,
    };
    verify_vendor_license(&token, &policy)
        .map(Some)
        .map_err(|e| {
            let hint = match &e {
                LicenseError::IssuerRoleNotAccepted { role: "cloud", .. } => {
                    " An mcpg.cloud licence reaches a managed or enrolled gateway through the \
                     platform; a self-hosted gateway's `license:` block takes a self-host \
                     licence."
                }
                LicenseError::UntrustedIssuerKey(_) => {
                    " Licences issued before MCPG embedded its issuer keys must be re-issued."
                }
                _ => "",
            };
            anyhow::anyhow!("{e}.{hint}")
        })
        .context("configured license token failed verification; refusing to boot")
}

/// The claims of the `license:` block's licence, or the community tier when
/// none is configured or it has lapsed. For callers that only ask what the
/// deployment is licensed for (usage reporting); an unverifiable licence is an
/// error.
pub(crate) fn resolve_claims(config: &AppConfig) -> anyhow::Result<LicenseClaims> {
    match verify_license_block(config)? {
        Some(verified) if verified.claims.term(Utc::now().timestamp()) != LicenseTerm::Lapsed => {
            Ok(verified.claims)
        }
        _ => Ok(LicenseClaims::community(AUDIENCE_GATEWAY)),
    }
}

/// The licence delivery and bound plugin set of an attached gateway, shared
/// by the control-plane hooks that receive them and the boot and reload that
/// gate on them. One process attaches to at most one control plane.
pub(crate) mod platform {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    static DELIVERY: std::sync::LazyLock<ArcSwap<Delivery>> =
        std::sync::LazyLock::new(|| ArcSwap::from_pointee(Delivery::Pending));
    static BOUND: ArcSwapOption<BTreeSet<String>> = ArcSwapOption::const_empty();
    static CHANGED: tokio::sync::Notify = tokio::sync::Notify::const_new();
    static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static RESTARTED: AtomicBool = AtomicBool::new(false);
    static BOUND_CACHED: AtomicBool = AtomicBool::new(false);

    /// Counts the changes to the delivery and the bound set. Read before
    /// them, it tells a gate whether what it evaluated is still the latest.
    pub fn generation() -> u64 {
        GENERATION.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Whether the delivery or the bound set changed after `seen` was read
    /// from [`generation`].
    #[cfg(any(feature = "cp-attached", test))]
    pub fn changed_since(seen: u64) -> bool {
        generation() != seen
    }

    #[cfg(any(feature = "cp-attached", test))]
    fn record_change() {
        GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        CHANGED.notify_waiters();
    }

    /// Whether a process booting `config` gates on the platform's licence:
    /// it starts the control-plane agent exactly then.
    pub fn attached(config: &AppConfig) -> bool {
        cfg!(feature = "cp-attached") && config.gateway.control_plane.is_some()
    }

    /// The delivery `config` gates on when it boots a process.
    #[cfg(test)]
    pub fn delivery_for(config: &AppConfig) -> Arc<Delivery> {
        delivery_when(attached(config))
    }

    /// The delivery a process attached or not at its boot gates on.
    pub fn delivery_when(attached: bool) -> Arc<Delivery> {
        if attached {
            DELIVERY.load_full()
        } else {
            Arc::new(Delivery::Standalone)
        }
    }

    /// The bound plugin set a process attached or not at its boot gates on.
    pub fn bound_plugins_when(attached: bool) -> Option<Arc<BTreeSet<String>>> {
        if attached { BOUND.load_full() } else { None }
    }

    /// Record a delivery; returns whether it differs from the last one.
    #[cfg(any(feature = "cp-attached", test))]
    pub fn set_delivery(delivery: Delivery) -> bool {
        let changed = *DELIVERY.load_full() != delivery;
        if changed {
            DELIVERY.store(Arc::new(delivery));
            record_change();
        }
        changed
    }

    /// Record a delivery the control plane sent; returns whether the gateway
    /// now gates on something else. A licence that does not verify — signed
    /// with a key this release does not embed yet, damaged, or a cloud
    /// licence mcpg.cloud did not prove it delivered — says nothing about the
    /// org's plan, so it never replaces one that does: the gateway keeps
    /// gating on that one, which still lapses at the end of its own grace.
    ///
    /// The cached licence a restart counts on the proof kept with it
    /// ([`Origin::CachedProven`]) stands only until a control plane answers
    /// this process: what that control plane delivers replaces it, so one
    /// that cannot prove the delivery drops the cloud licence at once. A
    /// proven delivery of a licence that does not verify says nothing about
    /// the plan, so, as on a running gateway, the cached licence stays until
    /// its day ends.
    #[cfg(any(feature = "cp-attached", test))]
    pub fn receive_delivery(delivery: Delivery) -> bool {
        let current = DELIVERY.load_full();
        if matches!(current.origin(), Some(Origin::CachedProven { .. })) {
            if delivery.origin() == Some(Origin::Proven)
                && let Err(e) = verifies(&delivery)
                && verifies(&current).is_ok()
            {
                tracing::error!(
                    error = %e,
                    "license: the licence mcpg.cloud delivered does not verify; this gateway \
                     keeps the licence it cached until the day its proof holds ends"
                );
                return false;
            }
            return set_delivery(delivery);
        }
        let delivery = still_proven(&current, delivery);
        if let Err(e) = verifies(&delivery)
            && matches!(*current, Delivery::Delivered { .. })
            && verifies(&current).is_ok()
        {
            tracing::error!(
                error = %e,
                "license: the licence the control plane delivered does not verify; this \
                 gateway keeps gating on the last one that did"
            );
            return false;
        }
        set_delivery(delivery)
    }

    /// `delivery`, proven when it carries, for the same org, the licence
    /// mcpg.cloud already proved it delivered on a Channel of this process: a
    /// licence the process holds proven gains nothing from being sent again
    /// without a proof but the word on its refresh.
    #[cfg(any(feature = "cp-attached", test))]
    fn still_proven(current: &Delivery, delivery: Delivery) -> Delivery {
        match (current, delivery) {
            (
                Delivery::Delivered {
                    license_jwt: proven,
                    org_slug: proven_org,
                    origin: Origin::Proven,
                    ..
                },
                Delivery::Delivered {
                    license_jwt,
                    org_slug,
                    origin: Origin::Unproven,
                    refresh_failing,
                },
            ) if proven.trim() == license_jwt.trim() && *proven_org == org_slug => {
                Delivery::Delivered {
                    license_jwt,
                    org_slug,
                    origin: Origin::Proven,
                    refresh_failing,
                }
            }
            (_, delivery) => delivery,
        }
    }

    /// Whether the licence in `delivery` verifies. No licence (the org holds
    /// none) is the platform's word that the org runs on community.
    #[cfg(any(feature = "cp-attached", test))]
    fn verifies(delivery: &Delivery) -> Result<(), String> {
        match delivery {
            Delivery::Delivered {
                license_jwt,
                org_slug,
                origin,
                ..
            } if !license_jwt.trim().is_empty() => verify_delivered(
                license_jwt.trim(),
                org_slug,
                origin.at(Utc::now().timestamp()),
            )
            .map(|_| ()),
            _ => Ok(()),
        }
    }

    /// Record the bound plugin set the control plane sent this process;
    /// returns whether it changed.
    #[cfg(any(feature = "cp-attached", test))]
    pub fn set_bound_plugins(bound: Option<BTreeSet<String>>) -> bool {
        let changed = BOUND.load_full().as_deref() != bound.as_ref();
        if changed {
            BOUND.store(bound.map(Arc::new));
        }
        // A booting gateway that waits on a set read back at start is woken
        // by the control plane's own word, even when that is the same set.
        let was_cached = BOUND_CACHED.swap(false, Ordering::AcqRel);
        if changed || was_cached {
            record_change();
        }
        changed
    }

    /// Seed the gate with what the control plane delivered to the process
    /// before this one: the licence it last sent ([`Origin::Cached`], or
    /// [`Origin::CachedProven`] while the proof kept with it holds) and the
    /// plugin set of the last bundle it pushed, when either was kept.
    #[cfg(any(feature = "cp-attached", test))]
    pub fn seed_from_cache(delivery: Option<Delivery>, bound: Option<Option<BTreeSet<String>>>) {
        if let Some(delivery) = delivery {
            set_delivery(delivery);
            RESTARTED.store(true, Ordering::Release);
        }
        if let Some(bound) = bound {
            set_bound_plugins(bound);
            BOUND_CACHED.store(true, Ordering::Release);
            RESTARTED.store(true, Ordering::Release);
        }
    }

    /// Whether this process started with what the control plane delivered
    /// to the one before it.
    pub fn restarted() -> bool {
        RESTARTED.load(Ordering::Acquire)
    }

    /// Whether the bound plugin set is still the one read back at start.
    pub fn bound_from_cache() -> bool {
        BOUND_CACHED.load(Ordering::Acquire)
    }

    /// Forget a seed, for a test that set one.
    #[cfg(test)]
    pub(crate) fn clear_seed() {
        RESTARTED.store(false, Ordering::Release);
        BOUND_CACHED.store(false, Ordering::Release);
    }

    /// Resolves at the next delivery or bound-set change after it is enabled,
    /// or when [`slot_held`] records a refused Channel.
    pub fn next_change() -> tokio::sync::futures::Notified<'static> {
        CHANGED.notified()
    }

    static SLOT_FREES_AT: std::sync::Mutex<Option<tokio::time::Instant>> =
        std::sync::Mutex::new(None);

    /// Record that the control plane refused this process's Channel because
    /// another Channel of its instance holds the slot, and that the agent
    /// opens it again in `retry_in`. A booting gate then waits for the
    /// delivery that Channel brings instead of giving up first.
    #[cfg(any(feature = "cp-attached", test))]
    pub fn slot_held(retry_in: Duration) {
        *SLOT_FREES_AT.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(tokio::time::Instant::now() + retry_in);
        CHANGED.notify_waiters();
    }

    /// When the agent opens again the Channel [`slot_held`] last recorded
    /// refused.
    pub fn slot_frees_at() -> Option<tokio::time::Instant> {
        *SLOT_FREES_AT.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Forget a refused Channel, for a test that recorded one.
    #[cfg(test)]
    pub(crate) fn clear_slot() {
        *SLOT_FREES_AT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Held by every test that sets the process-wide delivery or bound set,
    /// since tests share the process.
    #[cfg(test)]
    pub(crate) async fn test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        LOCK.lock().await
    }
}

/// Gate `config` at boot. An attached gateway whose gated items wait on a
/// licence the control plane may still deliver waits up to [`LICENSE_WAIT`]
/// for it, so a pod boots with its plan instead of withholding what the plan
/// covers. Past the wait, the items that can be withheld are, and the others
/// refuse the boot.
///
/// A restart ([`platform::restarted`]) also waits while what it read back at
/// start is what keeps an item out — a delivery or a bound set the control
/// plane may since have replaced — and then lands where the running gateway
/// was: what can be withheld is, and the rest is loaded and held, with every
/// call refused, rather than refusing the boot.
///
/// While the control plane refuses this process's Channel because another
/// Channel of the instance holds its slot ([`platform::slot_held`]), the wait
/// runs until [`LICENSE_WAIT`] after the slot frees, by at most
/// [`MAX_SLOT_WAIT`] more.
pub(crate) async fn gate_at_boot(config: &AppConfig) -> anyhow::Result<GateOutcome> {
    gate_at_boot_within(config, LICENSE_WAIT).await
}

/// The longest a booting gateway waits, past its licence wait, for a Channel
/// slot another Channel of its instance holds: the longest a control plane
/// lets a silent Channel hold it, two missed heartbeats of the longest
/// interval a gateway runs plus slack.
const MAX_SLOT_WAIT: Duration = Duration::from_secs(125);

/// When a boot that started at `started` and waits `wait` for its licence
/// stops waiting: `wait` after the agent opens again a Channel refused for a
/// held slot, when that is later, by at most [`MAX_SLOT_WAIT`].
fn boot_deadline(
    started: tokio::time::Instant,
    wait: Duration,
    slot_frees_at: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let base = started + wait;
    slot_frees_at.map_or(base, |at| (at + wait).clamp(base, base + MAX_SLOT_WAIT))
}

async fn gate_at_boot_within(config: &AppConfig, wait: Duration) -> anyhow::Result<GateOutcome> {
    let started = tokio::time::Instant::now();
    let admitted = BTreeSet::new();
    let mut announced = false;
    let mut announced_slot = false;
    loop {
        let deadline = boot_deadline(started, wait, platform::slot_frees_at());
        // Enabled before reading, so a delivery landing mid-evaluation still
        // wakes the wait below.
        let next_change = platform::next_change();
        tokio::pin!(next_change);
        next_change.as_mut().enable();
        let generation = platform::generation();
        let attached = platform::attached(config);
        let delivery = platform::delivery_when(attached);
        let bound = platform::bound_plugins_when(attached);
        let restart = attached && platform::restarted();
        let delivery_cached = restart && delivery.origin().is_some_and(Origin::is_cached);
        let bound_cached = restart && platform::bound_from_cache();
        let inputs = GateInputs {
            delivery: &delivery,
            bound_plugins: bound.as_deref(),
            admitted: &admitted,
            withheld: &[],
            restart,
            now: Utc::now().timestamp(),
        };
        let can_wait = tokio::time::Instant::now() < deadline;
        let waits = |hold: &HoldReason| {
            hold.may_resolve_by_delivery() || hold.rests_on_cache(delivery_cached, bound_cached)
        };
        let waiting_on = match evaluate(config, &inputs) {
            Ok(outcome) if can_wait && outcome.hold.as_ref().is_some_and(waits) => outcome
                .status
                .withheld
                .into_iter()
                .chain(outcome.status.held)
                .collect(),
            Ok(mut outcome) => {
                outcome.platform_generation = generation;
                report(&outcome);
                return Ok(outcome);
            }
            Err(refusal) if can_wait && refusal.waits_for_delivery() => refusal.awaiting,
            Err(refusal) => return Err(refusal.into()),
        };
        if !announced {
            tracing::info!(
                wait = ?LICENSE_WAIT,
                items = ?waiting_on,
                "license: waiting for the control plane to deliver this gateway's licence"
            );
            announced = true;
        }
        if !announced_slot && deadline > started + wait {
            tracing::warn!(
                until = ?deadline.saturating_duration_since(tokio::time::Instant::now()),
                "license: another Channel of this gateway's instance holds its slot at the \
                 control plane; waiting for the slot to free"
            );
            announced_slot = true;
        }
        let _ = tokio::time::timeout_at(deadline, next_change).await;
    }
}

/// Gate a reload of a gateway that runs as `running` says, keeping what it
/// already loaded. The caller [`report`]s the outcome once the gateway runs
/// on it, so the status never names as withheld what a failed reload left
/// loaded.
///
/// Whether the gateway is attached is what it was at boot, whatever the
/// reloaded config says: the control-plane agent starts at boot and keeps
/// running, so a reload that drops `gateway.control_plane` never makes a
/// connected gateway's own `license:` block or loaded items count as a
/// standalone gateway's, and one that adds it attaches nothing.
pub(crate) fn gate_at_reload(
    config: &AppConfig,
    running: &LicenseRuntimeState,
) -> anyhow::Result<GateOutcome> {
    let generation = platform::generation();
    let attached = running
        .attached
        .unwrap_or_else(|| platform::attached(config));
    let delivery = platform::delivery_when(attached);
    let bound = platform::bound_plugins_when(attached);
    let mut outcome = evaluate(
        config,
        &GateInputs {
            delivery: &delivery,
            bound_plugins: bound.as_deref(),
            admitted: &running.admitted,
            withheld: &running.withheld,
            restart: false,
            now: Utc::now().timestamp(),
        },
    )?;
    outcome.platform_generation = generation;
    Ok(outcome)
}

/// What the gate left running, as the runtime carries it.
#[derive(Clone, Debug, Default)]
pub struct LicenseRuntimeState {
    pub admitted: BTreeSet<String>,
    pub withheld: Vec<String>,
    pub tool_hold: Option<String>,
    /// [`platform::generation`] the runtime was gated at.
    pub platform_generation: u64,
    /// When the delivered licence this runtime loaded gated items under ends
    /// its grace, or, read back at a restart, stops counting on the proof kept
    /// with it (unix seconds). No delivery need arrive then, so the gateway
    /// gates itself again at that time.
    pub lapses_at: Option<i64>,
    /// Whether the process was attached to a control plane when it booted,
    /// which every later gate keeps. `None` only on a runtime no gate ran
    /// for.
    pub attached: Option<bool>,
    /// Set while a surface of the embedded authorization server is held: its
    /// OAuth endpoints answer with this instead of serving, since a held
    /// surface is part of the server and a sign-in or token it issued would
    /// run the feature the licence does not cover.
    pub authorization_server_hold: Option<String>,
    /// Set while MCP Events webhook delivery is held: nothing is delivered
    /// and no webhook subscription is made, and both resume when a licence
    /// covers it again.
    pub events_hold: Option<String>,
}

impl LicenseRuntimeState {
    /// Why the gateway serves less than its config while it runs: a hold
    /// that refuses every call, or, on an attached gateway, a delivered
    /// licence that keeps failing to reach it. Readiness and health report
    /// it as degraded, never as failed: the gateway still serves its
    /// listings, and a restart would bring no licence.
    pub fn degradation(&self) -> Option<String> {
        if let Some(hold) = &self.tool_hold {
            return Some(hold.clone());
        }
        let failures = regate_failures();
        (self.attached == Some(true) && failures > 0).then(|| {
            format!(
                "the delivered licence has not reached the running gateway: {failures} \
                 regate(s) in a row failed, and it is tried again"
            )
        })
    }

    /// Whether a licence delivery or bound plugin set arrived after this
    /// runtime was gated, so the gateway has to be gated again to run on it.
    #[cfg(any(feature = "cp-attached", test))]
    pub(crate) fn is_behind_platform(&self) -> bool {
        platform::changed_since(self.platform_generation)
    }

    /// Gate `config` again on the latest delivery and bound set, as a reload
    /// of this runtime would. `Ok(true)` when the answer withholds or holds
    /// other items than this runtime does, which only a reload applies and
    /// publishes; otherwise the licence status is published here.
    #[cfg(any(feature = "cp-attached", test))]
    pub(crate) fn regate(&self, config: &AppConfig) -> anyhow::Result<bool> {
        let outcome = gate_at_reload(config, self)?;
        let changed =
            outcome.status.withheld != self.withheld || outcome.tool_hold() != self.tool_hold;
        if !changed {
            report(&outcome);
        }
        Ok(changed)
    }
}

impl From<&GateOutcome> for LicenseRuntimeState {
    fn from(outcome: &GateOutcome) -> Self {
        LicenseRuntimeState {
            admitted: outcome.admitted.clone(),
            withheld: outcome
                .withheld
                .iter()
                .map(|w| w.plugin_id.clone())
                .collect(),
            tool_hold: outcome.tool_hold(),
            platform_generation: outcome.platform_generation,
            lapses_at: [
                outcome.status.grace_ends_at.map(|t| t.timestamp()),
                outcome.counts_until,
            ]
            .into_iter()
            .flatten()
            .min()
            .filter(|_| {
                outcome.status.source == LicenseSource::Platform
                    && outcome.status.state != LicenseTerm::Lapsed.as_str()
                    && !outcome.admitted.is_empty()
            }),
            attached: Some(outcome.attached),
            authorization_server_hold: outcome.authorization_server_hold(),
            events_hold: outcome.events_hold(),
        }
    }
}

static REGATE_FAILURES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Record whether a regate of the running gateway reached it: failures in a
/// row count until one does.
#[cfg(any(feature = "cp-attached", test))]
pub(crate) fn record_regate(reached: bool) {
    use std::sync::atomic::Ordering;
    if reached {
        REGATE_FAILURES.store(0, Ordering::Release);
    } else {
        REGATE_FAILURES.fetch_add(1, Ordering::AcqRel);
    }
}

/// Regates in a row that did not reach the running gateway.
pub(crate) fn regate_failures() -> u32 {
    REGATE_FAILURES.load(std::sync::atomic::Ordering::Acquire)
}

static STATUS: ArcSwapOption<LicenseStatus> = ArcSwapOption::const_empty();

/// The status of the licence the last boot or reload ran under.
pub fn current_status() -> Option<Arc<LicenseStatus>> {
    STATUS.load_full()
}

/// Log the outcome, publish it as the current status and as metrics.
pub(crate) fn report(outcome: &GateOutcome) {
    let status = &outcome.status;
    let expires = status.expires_at.map(|t| t.format("%Y-%m-%d").to_string());
    let grace_ends = status
        .grace_ends_at
        .map(|t| t.format("%Y-%m-%d").to_string());
    match status.state {
        "expiring" if status.refresh_failing => tracing::warn!(
            plan = %status.plan,
            expires = ?expires,
            "license: the control plane reports that it cannot renew this licence; it keeps \
             its plugins and features until it expires and through the grace period after"
        ),
        "expiring" => tracing::warn!(
            plan = %status.plan,
            expires = ?expires,
            "license: the licence expires within 30 days; renew it to keep its plugins and \
             features past the grace period"
        ),
        "grace" => tracing::error!(
            plan = %status.plan,
            expired = ?expires,
            grace_ends = ?grace_ends,
            "license: the licence has expired; its plugins and features keep running until \
             the grace period ends"
        ),
        "lapsed" => tracing::error!(
            plan = %status.plan,
            expired = ?expires,
            grace_ended = ?grace_ends,
            "license: the licence expired and its grace period is over; gated plugins and \
             features are no longer licensed"
        ),
        _ => {}
    }
    if status.non_production {
        tracing::warn!(
            source = status.source.as_str(),
            "license: NON-PRODUCTION deployment — entitlement-gated plugins and features run \
             under the licence's non-production grant; production use requires a licence \
             without that mark"
        );
    }
    if !outcome.withheld.is_empty() {
        tracing::warn!(
            plugins = ?status.withheld,
            reason = %outcome.hold.as_ref().map(HoldReason::describe).unwrap_or_default(),
            tool_calls_refused = outcome.tool_hold().is_some(),
            "license: plugins withheld until a licence covers them"
        );
    }
    if !outcome.held.is_empty() {
        tracing::error!(
            items = ?status.held,
            reason = %outcome.hold.as_ref().map(HoldReason::describe).unwrap_or_default(),
            "license: the delivered licence no longer covers items this gateway cannot run \
             without; every tool call, prompt, resource read and completion is refused until \
             a licence covers them"
        );
    }
    publish(status);
}

fn publish(status: &LicenseStatus) {
    const INFO: &str = "mcpg_license_info";
    if let Some(previous) = STATUS.load_full()
        && (previous.plan != status.plan
            || previous.source != status.source
            || previous.state != status.state
            || previous.non_production != status.non_production)
    {
        metrics::gauge!(
            INFO,
            "plan" => previous.plan.clone(),
            "source" => previous.source.as_str(),
            "state" => previous.state,
            "non_production" => previous.non_production.to_string(),
        )
        .set(0.0);
    }
    metrics::gauge!(
        INFO,
        "plan" => status.plan.clone(),
        "source" => status.source.as_str(),
        "state" => status.state,
        "non_production" => status.non_production.to_string(),
    )
    .set(1.0);
    metrics::gauge!("mcpg_license_expires_at_seconds")
        .set(status.expires_at.map_or(0.0, |t| t.timestamp() as f64));
    metrics::gauge!("mcpg_license_withheld_plugins").set(status.withheld.len() as f64);
    metrics::gauge!("mcpg_license_held_items").set(status.held.len() as f64);
    let published = Arc::new(status.clone());
    #[cfg(test)]
    let _ = REPORTED_IN_TASK.try_with(|reported| {
        *reported.borrow_mut() = Some(Arc::clone(&published));
    });
    STATUS.store(Some(published));
}

#[cfg(test)]
tokio::task_local! {
    /// The status the current test task last published. Every test that
    /// boots or reloads a gateway writes the global status, so a test that
    /// checks what it published itself reads this instead.
    static REPORTED_IN_TASK: std::cell::RefCell<Option<Arc<LicenseStatus>>>;
}

/// Run `test` with its own record of the statuses it publishes.
#[cfg(test)]
pub(crate) async fn with_reported_status<F: std::future::Future>(test: F) -> F::Output {
    REPORTED_IN_TASK
        .scope(std::cell::RefCell::new(None), test)
        .await
}

/// The status the current test last published, under
/// [`with_reported_status`].
#[cfg(test)]
pub(crate) fn reported_status() -> Option<Arc<LicenseStatus>> {
    REPORTED_IN_TASK
        .try_with(|reported| reported.borrow().clone())
        .ok()
        .flatten()
}

/// Whether the daily reminder repeats `status`'s warnings: a non-production
/// declaration, withheld or held items, or a licence that may run out (an
/// mcpg.cloud licence only once its refresh fails or it is past `exp`).
fn needs_reminder(status: &LicenseStatus) -> bool {
    status.non_production
        || !status.withheld.is_empty()
        || !status.held.is_empty()
        || matches!(status.state, "expiring" | "grace" | "lapsed" | "pending")
}

/// Repeat the licence warnings once a day for as long as they apply, so an
/// expiry or a non-production declaration is not one line at boot.
pub(crate) fn spawn_reminder() {
    static STARTED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(status) = current_status() else {
                continue;
            };
            if needs_reminder(&status) {
                tracing::warn!(
                    plan = %status.plan,
                    source = status.source.as_str(),
                    state = status.state,
                    refresh_failing = status.refresh_failing,
                    expires_at = ?status.expires_at,
                    non_production = status.non_production,
                    withheld = ?status.withheld,
                    held = ?status.held,
                    "license: reminder"
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_control_plane_license::license::KeyEnvironment;
    use mcpg_control_plane_license::trust::test_override;

    fn origin_of(
        license_jwt: &str,
        org_slug: &str,
        proof: &str,
        channel: ChannelBinding<'_>,
        now: i64,
    ) -> Origin {
        judge_delivery(license_jwt, org_slug, proof, channel, now).origin
    }

    fn config_with_plugins(ids: &[&str], license_yaml: &str) -> AppConfig {
        let plugins: String = ids
            .iter()
            .map(|id| {
                let class = id.split('.').nth(2).unwrap_or("backend");
                format!("  - id: {id}\n    class: {class}\n    source: {{ path: /tmp/x.so }}\n")
            })
            .collect();
        let yaml = format!("plugins:\n{plugins}{license_yaml}");
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    fn claims_for(plan: &str, aud: &str) -> LicenseClaims {
        let mut claims = LicenseClaims::community(aud);
        claims.iss = "https://license.test".into();
        claims.exp = Utc::now().timestamp() + 3600;
        let (entitlements, quotas) = license::plan_envelope(plan);
        claims.plugin_entitlements = entitlements;
        claims.quotas = quotas;
        claims.features = license::features_for(plan);
        claims.plan = plan.into();
        claims
    }

    /// A self-host licence for `plan`, signed by a key this test trusts.
    fn signed_license(plan: &str) -> String {
        test_override::issue(
            IssuerRole::SelfHost,
            KeyEnvironment::Production,
            &claims_for(plan, AUDIENCE_GATEWAY),
        )
    }

    fn license_block(token: &str) -> String {
        format!("license:\n  token: {token}\n")
    }

    /// A `license:` block carrying a self-host licence for `plan`.
    fn license_yaml_for(plan: &str) -> String {
        license_block(&signed_license(plan))
    }

    fn inputs<'a>(
        delivery: &'a Delivery,
        admitted: &'a BTreeSet<String>,
        now: i64,
    ) -> GateInputs<'a> {
        GateInputs {
            delivery,
            bound_plugins: None,
            admitted,
            withheld: &[],
            restart: false,
            now,
        }
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    #[test]
    fn free_plugins_pass_unlicensed() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.http", "dev.mcpg.transform.jsonata"], "");
        assert!(enforce_license_gate(&cfg).is_ok());
    }

    #[test]
    fn gated_plugin_refuses_without_a_license() {
        let cfg = config_with_plugins(&["dev.mcpg.payment.ucp"], "");
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("payment.ucp"), "{err}");
        assert!(err.contains("non_production_use"), "{err}");
    }

    #[test]
    fn alias_plus_ref_is_gated_on_the_manifest_id() {
        let yaml = "plugins:\n  - id: my-sso\n    ref: dev.mcpg.identity.saml\n    class: identity_provider\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_license_gate(&cfg).is_err());
    }

    #[test]
    fn non_production_declaration_loads_gated_plugins_and_marks_the_status() {
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml"],
            "license:\n  non_production_use: true\n",
        );
        assert!(enforce_license_gate(&cfg).is_ok());
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("admitted");
        assert!(outcome.status.non_production);
        assert_eq!(
            outcome.status.source,
            LicenseSource::NonProductionDeclaration
        );
        let health = serde_json::to_value(&outcome.status).unwrap();
        assert_eq!(health["non_production"], serde_json::json!(true));
    }

    /// Records the gauges and counters a call touches, as `name{k=v,…}`.
    #[derive(Default)]
    struct Gauges(std::sync::Mutex<Vec<String>>);

    impl Gauges {
        fn touch(&self, key: &metrics::Key) {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            self.0
                .lock()
                .unwrap()
                .push(format!("{}{{{}}}", key.name(), labels.join(",")));
        }
    }

    impl metrics::Recorder for Gauges {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            self.touch(key);
            metrics::Counter::noop()
        }
        fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            self.touch(key);
            metrics::Gauge::noop()
        }
        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// The non-production declaration is a metric label and a field of the
    /// status the admin health endpoint serves, not only a boot line.
    #[tokio::test]
    async fn the_status_is_published_with_the_non_production_label() {
        // The published status is process-wide, as the delivery is.
        let _platform = platform::test_lock().await;
        let cfg = config_with_plugins(&[], "license:\n  non_production_use: true\n");
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("admitted");
        let gauges = Gauges::default();
        metrics::with_local_recorder(&gauges, || publish(&outcome.status));
        let seen = gauges.0.lock().unwrap().clone();
        assert!(
            seen.contains(
                &"mcpg_license_info{plan=non-production,source=non_production_declaration,\
                  state=unlicensed,non_production=true}"
                    .to_owned()
            ),
            "{seen:?}"
        );
        assert!(
            seen.iter()
                .any(|g| g.starts_with("mcpg_license_expires_at_seconds"))
        );
    }

    #[test]
    fn disabled_entries_and_third_party_ids_are_ignored() {
        let yaml = "plugins:\n  - id: dev.mcpg.cluster.redis\n    class: cluster\n    source: { path: /tmp/x.so }\n    disabled: true\n  - id: acme.payment.custom\n    class: payment\n    source: { path: /tmp/x.so }\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(enforce_license_gate(&cfg).is_ok());
    }

    #[test]
    fn entitling_token_admits_and_lesser_token_refuses() {
        let license_yaml = license_yaml_for("team");
        // Team licenses saml + policy...
        let cfg = config_with_plugins(
            &["dev.mcpg.identity.saml", "dev.mcpg.policy.cedar"],
            &license_yaml,
        );
        assert!(enforce_license_gate(&cfg).is_ok());
        // ...but not kerberos (enterprise-only feature)...
        let cfg = config_with_plugins(&["dev.mcpg.identity.kerberos"], &license_yaml);
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("sso.kerberos"), "{err}");
        // ...nor a cluster coordinator: high availability is Enterprise.
        for coordinator in ["dev.mcpg.cluster.redis", "dev.mcpg.cluster.nats"] {
            let cfg = config_with_plugins(&[coordinator], &license_yaml);
            let err = enforce_license_gate(&cfg).unwrap_err().to_string();
            assert!(err.contains(coordinator), "{err}");
            let cfg = config_with_plugins(&[coordinator], &license_yaml_for("enterprise"));
            enforce_license_gate(&cfg).expect("enterprise licenses the coordinators");
        }
    }

    /// The trust anchor is compiled in: a licence a customer signs with a key
    /// of their own does not verify, whatever `pubkey_pem` names.
    #[test]
    fn a_licence_signed_by_a_key_outside_the_embedded_set_is_refused() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let own_key = SigningKey::generate(&mut rand::rng());
        let token = test_override::sign(&claims_for("enterprise", AUDIENCE_GATEWAY), &own_key);
        let pem = own_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let block = format!(
            "license:\n  token: {token}\n  pubkey_pem: |\n{}",
            pem.lines()
                .map(|l| format!("    {l}\n"))
                .collect::<String>()
        );
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &block);
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        assert!(
            err.contains("not signed by an MCPG licence issuer key"),
            "{err}"
        );
    }

    /// `pubkey_pem` anchors nothing, so a value it cannot even parse does not
    /// stop an MCPG-signed licence.
    #[test]
    fn pubkey_pem_is_ignored() {
        let block = format!(
            "{}  pubkey_pem: not-a-key\n",
            license_yaml_for("enterprise")
        );
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &block);
        enforce_license_gate(&cfg).expect("pubkey_pem plays no part");
    }

    /// A cloud licence is not a self-host gateway licence, even when its key
    /// is trusted.
    #[test]
    fn a_cloud_licence_in_the_license_block_is_refused() {
        let mut claims = claims_for("team", AUDIENCE_GATEWAY_MANAGED);
        claims.aud.push(AUDIENCE_GATEWAY.into());
        let token = test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims);
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &license_block(&token));
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        assert!(err.contains("cloud issuer key"), "{err}");
        assert!(err.contains("through the platform"), "{err}");
    }

    /// A staging key signs only non-production licences, and a gateway
    /// running one says so.
    #[test]
    fn a_staging_licence_is_admitted_and_marked_non_production() {
        let mut claims = claims_for("enterprise", AUDIENCE_GATEWAY);
        claims.non_production = true;
        let token = test_override::issue(IssuerRole::SelfHost, KeyEnvironment::Staging, &claims);
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &license_block(&token));
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("admitted");
        assert!(outcome.status.non_production);
        assert_eq!(outcome.status.source, LicenseSource::LicenseBlock);

        let unmarked = test_override::issue(
            IssuerRole::SelfHost,
            KeyEnvironment::Staging,
            &claims_for("enterprise", AUDIENCE_GATEWAY),
        );
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &license_block(&unmarked));
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        assert!(err.contains("staging issuer key"), "{err}");
    }

    #[test]
    fn garbage_token_refuses_boot_even_for_free_configs_with_gated_entries() {
        let cfg = config_with_plugins(&["dev.mcpg.payment.ucp"], "license:\n  token: not-a-jwt\n");
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        assert!(err.contains("failed verification"), "{err}");
    }

    /// `license.token` takes `${env.X}` and `${secret.NAME}` like every other
    /// config secret, so it does not have to sit in the config file.
    #[test]
    fn license_token_resolves_env_and_mounted_secret_references() {
        const TOKEN_ENV: &str = "MCPGTEST_LICENSE_GATE_TOKEN";
        let token = signed_license("enterprise");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("LICENSE_TOKEN"), &token).unwrap();
        // SAFETY: test-only; no other test reads this variable.
        unsafe { std::env::set_var(TOKEN_ENV, &token) };
        let secrets_dir = format!("gateway:\n  secrets:\n    dir: {}\n", dir.path().display());
        for token_ref in [
            format!("${{env.{TOKEN_ENV}}}"),
            "${secret.LICENSE_TOKEN}".to_owned(),
        ] {
            let cfg = config_with_plugins(
                &["dev.mcpg.cluster.redis"],
                &format!("{secrets_dir}license:\n  token: \"{token_ref}\"\n"),
            );
            let claims = resolve_claims(&cfg).unwrap_or_else(|e| panic!("{token_ref}: {e:#}"));
            assert_eq!(claims.plan, "enterprise", "{token_ref}");
            enforce_license_gate(&cfg).unwrap_or_else(|e| panic!("{token_ref}: {e:#}"));
        }
        unsafe { std::env::remove_var(TOKEN_ENV) };
    }

    /// A reference that does not resolve refuses the boot, naming the field
    /// and the reference; a token that resolves to nothing is not the
    /// community tier.
    #[test]
    fn an_unresolvable_license_reference_refuses_and_names_it() {
        const EMPTY_ENV: &str = "MCPGTEST_LICENSE_GATE_EMPTY_TOKEN";
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            "license:\n  token: \"${env.MCPGTEST_LICENSE_GATE_NEVER_SET}\"\n",
        );
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        assert!(
            err.contains("license.token") && err.contains("MCPGTEST_LICENSE_GATE_NEVER_SET"),
            "{err}"
        );

        // SAFETY: test-only; no other test reads this variable.
        unsafe { std::env::set_var(EMPTY_ENV, "") };
        let cfg = config_with_plugins(
            &["dev.mcpg.payment.ucp"],
            &format!("license:\n  token: \"${{env.{EMPTY_ENV}}}\"\n"),
        );
        let err = format!("{:#}", enforce_license_gate(&cfg).unwrap_err());
        unsafe { std::env::remove_var(EMPTY_ENV) };
        assert!(err.contains("resolves to an empty value"), "{err}");
    }

    /// `examples/deployments/`: beside this crate in a standalone checkout,
    /// two levels up in the workspace, or where a sandboxed runner staged it.
    fn deployments_dir() -> std::path::PathBuf {
        if let (Ok(rel), Ok(root)) = (
            std::env::var("MCPG_TEST_DEPLOYMENTS_DIR"),
            std::env::var("TEST_SRCDIR"),
        ) {
            return std::path::PathBuf::from(root).join(rel);
        }
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let local = manifest.join("examples/deployments");
        if local.is_dir() {
            return local;
        }
        manifest.join("../../examples/deployments")
    }

    /// Every shipped deployment template with a `license:` block resolves its
    /// license once it is installed the way the template's README says: the
    /// MCPG-issued token file mounted.
    #[test]
    fn the_licensed_deployment_templates_resolve_their_installed_license() {
        let dir = deployments_dir();
        let token = signed_license("enterprise");
        let scratch = tempfile::tempdir().unwrap();
        let token_file = scratch.path().join("license.jwt");
        std::fs::write(&token_file, &token).unwrap();

        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|entry| entry.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
            .collect();
        paths.sort();
        let mut licensed = Vec::new();
        let mut failures = Vec::new();
        for path in paths {
            let yaml = std::fs::read_to_string(&path).unwrap();
            let mut cfg: AppConfig =
                serde_yaml::from_str(&yaml).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            if cfg.license.token.is_none() && cfg.license.token_file.is_none() {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if cfg.license.pubkey_pem.is_some() {
                failures.push(format!("{name}: still sets the ignored license.pubkey_pem"));
            }
            cfg.license.token = None;
            cfg.license.token_file = Some(token_file.clone());
            match resolve_claims(&cfg).and_then(|claims| {
                anyhow::ensure!(claims.plan == "enterprise", "plan {}", claims.plan);
                enforce_license_gate(&cfg)
            }) {
                Ok(()) => licensed.push(name),
                Err(e) => failures.push(format!("{name}: {e:#}")),
            }
        }

        assert!(failures.is_empty(), "{failures:#?}");
        assert!(
            licensed.len() >= 6,
            "expected the six licensed templates under {}; resolved {licensed:?}",
            dir.display()
        );
    }

    // ── expiry ───────────────────────────────────────────────────────────

    const DAY: i64 = 86_400;

    fn license_expiring_at(plan: &str, exp: i64) -> String {
        let mut claims = claims_for(plan, AUDIENCE_GATEWAY);
        claims.exp = exp;
        claims.nbf = exp - 400 * DAY;
        claims.iat = claims.nbf;
        license_block(&test_override::issue(
            IssuerRole::SelfHost,
            KeyEnvironment::Production,
            &claims,
        ))
    }

    #[test]
    fn a_licence_close_to_expiry_still_admits_and_says_so() {
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis"],
            &license_expiring_at("enterprise", now() + 10 * DAY),
        );
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("admitted");
        assert_eq!(outcome.status.state, "expiring");
        assert!(outcome.status.expires_at.is_some());
    }

    /// Inside the grace period an expired licence still grants its plan, so a
    /// renewal in procurement does not take the gateway down.
    #[test]
    fn an_expired_licence_keeps_its_plan_through_the_grace_period() {
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis", "dev.mcpg.payment.ucp"],
            &license_expiring_at("enterprise", now() - 3 * DAY),
        );
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("admitted in grace");
        assert_eq!(outcome.status.state, "grace");
        assert!(outcome.withheld.is_empty());
        enforce_license_gate(&cfg).expect("the standalone gate admits it too");
    }

    /// Past the grace period the gated plugins that can go without opening
    /// anything are withheld; the free parts keep running, and tool calls are
    /// refused while a withheld tool gate would have judged them.
    #[test]
    fn a_lapsed_licence_withholds_what_fails_closed() {
        let cfg = config_with_plugins(
            &[
                "dev.mcpg.payment.ucp",
                "dev.mcpg.backend.kafka",
                "dev.mcpg.backend.http",
            ],
            &license_expiring_at("enterprise", now() - 20 * DAY),
        );
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("free parts run");
        assert_eq!(outcome.status.state, "lapsed");
        assert_eq!(
            outcome.status.withheld,
            vec!["dev.mcpg.payment.ucp", "dev.mcpg.backend.kafka"]
        );
        assert_eq!(
            withheld_backend_kinds(&outcome),
            BTreeSet::from(["kafka".to_owned()])
        );
        let hold = outcome.tool_hold().expect("a tool gate is withheld");
        assert!(
            hold.contains("dev.mcpg.payment.ucp") && hold.contains("expired on"),
            "{hold}"
        );

        let mut effective = cfg.clone();
        withhold(&mut effective, &outcome);
        let disabled: Vec<&str> = effective
            .plugins
            .iter()
            .filter(|p| p.disabled)
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(disabled, ["dev.mcpg.payment.ucp", "dev.mcpg.backend.kafka"]);
    }

    /// A lapsed licence cannot leave out what the gateway's security or
    /// coordination rests on; that config is refused, naming the dates.
    #[test]
    fn a_lapsed_licence_refuses_what_cannot_be_withheld() {
        let exp = now() - 20 * DAY;
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis"],
            &license_expiring_at("enterprise", exp),
        );
        let err = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(&format!("expired on {}", day(exp))), "{err}");
        assert!(err.contains("grace period ended on"), "{err}");
    }

    /// A reload keeps what the running gateway already loaded, so a secret
    /// rotation after the licence lapsed does not fail on the licence.
    #[test]
    fn a_reload_keeps_what_the_running_gateway_loaded() {
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis", "dev.mcpg.payment.ucp"],
            &license_expiring_at("enterprise", now() - 20 * DAY),
        );
        let running: BTreeSet<String> = [
            "plugin:dev.mcpg.cluster.redis".to_owned(),
            "plugin:dev.mcpg.payment.ucp".to_owned(),
        ]
        .into();
        let outcome = evaluate(&cfg, &inputs(&Delivery::Standalone, &running, now()))
            .expect("nothing new needs the licence");
        assert!(outcome.withheld.is_empty());
        assert_eq!(outcome.admitted, running);
    }

    // ── attached gateways ────────────────────────────────────────────────

    const ATTACHED: &str = "gateway:\n  control_plane:\n    url: http://127.0.0.1:9\n    \
                            enrollment_url: http://127.0.0.1:9\n";
    const PROVENANCE: &str =
        "cloud:\n  provenance:\n    cluster_id: cell-1\n    namespace: tenant-acme\n";

    fn cloud_licence(plan: &str, tenant: &str) -> String {
        let mut claims = claims_for(plan, "mcpg-cp");
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = tenant.into();
        test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims)
    }

    /// `token` delivered by mcpg.cloud, with a proof that verified.
    fn delivered(token: &str, org: &str) -> Delivery {
        delivered_as(token, org, Origin::Proven)
    }

    fn delivered_as(token: &str, org: &str, origin: Origin) -> Delivery {
        Delivery::received(token.into(), org.into(), origin)
    }

    /// A `gateway.control_plane` block lets no gated plugin through: with no
    /// licence delivered, a gated plugin waits instead of loading.
    #[test]
    fn a_control_plane_block_does_not_skip_the_plugin_gate() {
        let cfg = config_with_plugins(&["dev.mcpg.payment.ucp"], ATTACHED);
        assert!(cfg.gateway.control_plane.is_some());
        let err = enforce_license_gate(&cfg).unwrap_err().to_string();
        assert!(err.contains("payment.ucp"), "{err}");

        let outcome = evaluate(&cfg, &inputs(&Delivery::Pending, &BTreeSet::new(), now()))
            .expect("the tool gate is withheld, the rest runs");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.payment.ucp"]);
        assert!(outcome.tool_hold().unwrap().contains("not delivered"));

        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let refusal =
            evaluate(&cfg, &inputs(&Delivery::Pending, &BTreeSet::new(), now())).unwrap_err();
        assert!(refusal.waits_for_delivery());
        assert!(refusal.to_string().contains("not delivered"), "{refusal}");
    }

    /// The org licence the control plane delivers admits what its plan
    /// covers — and only for the org the gateway is enrolled into.
    #[test]
    fn a_delivered_cloud_licence_admits_for_its_own_org_only() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let token = cloud_licence("enterprise", "acme");
        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&token, "acme"), &BTreeSet::new(), now()),
        )
        .expect("enterprise covers cluster.redis");
        assert_eq!(outcome.status.source, LicenseSource::Platform);
        assert_eq!(outcome.status.plan, "enterprise");

        let refusal = evaluate(
            &cfg,
            &inputs(&delivered(&token, "other-org"), &BTreeSet::new(), now()),
        )
        .unwrap_err();
        assert!(
            refusal.to_string().contains("not to `other-org`"),
            "{refusal}"
        );
    }

    /// A licence the platform delivers that the org's plan does not cover is
    /// withheld where it can be, not a config error the tenant cannot fix.
    #[test]
    fn a_delivered_licence_that_lacks_a_plugin_withholds_it() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let token = cloud_licence("pro", "acme");
        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&token, "acme"), &BTreeSet::new(), now()),
        )
        .expect("withheld");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert!(outcome.tool_hold().is_none());
    }

    /// A managed licence with the platform-coordination grant (one that sells
    /// clustering without the `cluster.*` plugins) runs the coordinator the
    /// platform adds to a multi-replica gateway, and only that one.
    #[test]
    fn a_managed_licence_admits_the_platform_coordinator_only() {
        let mut claims = claims_for("pro", "mcpg-cp");
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = "acme".into();
        claims
            .features
            .push(license::FEATURE_PLATFORM_COORDINATION.into());
        let token = test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims);
        let delivery = delivered(&token, "acme");

        let cfg = config_with_plugins(&["dev.mcpg.cluster.nats"], ATTACHED);
        evaluate(&cfg, &inputs(&delivery, &BTreeSet::new(), now()))
            .expect("the platform coordinator runs");
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let refusal = evaluate(&cfg, &inputs(&delivery, &BTreeSet::new(), now())).unwrap_err();
        assert!(refusal.to_string().contains("cluster.redis"), "{refusal}");
    }

    /// A booting attached gateway waits for the control plane to deliver the
    /// licence its gated items need, instead of failing or withholding them,
    /// and boots with it; a delivery after the gate ran leaves the runtime
    /// behind until it is gated again.
    #[tokio::test]
    async fn an_attached_boot_waits_for_the_delivered_licence() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        let boot_with_delivery_later = |cfg: AppConfig, token: String| async move {
            platform::set_delivery(Delivery::Pending);
            let started = std::time::Instant::now();
            let deliver = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                platform::set_delivery(delivered(&token, "acme"));
            });
            let outcome = gate_at_boot(&cfg)
                .await
                .expect("boots once the licence arrives");
            deliver.await.unwrap();
            assert!(started.elapsed() >= Duration::from_millis(300));
            outcome
        };

        // A coordinator cannot be withheld.
        let outcome = boot_with_delivery_later(cfg, cloud_licence("enterprise", "acme")).await;
        assert_eq!(outcome.status.source, LicenseSource::Platform);
        assert_eq!(outcome.status.plan, "enterprise");

        // A backend could be withheld, but the org's plan covers it: the pod
        // boots with it rather than without it.
        let kafka = || config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let outcome = boot_with_delivery_later(kafka(), cloud_licence("enterprise", "acme")).await;
        assert!(outcome.withheld.is_empty(), "{:?}", outcome.status.withheld);
        assert_eq!(outcome.status.plan, "enterprise");

        // A runtime gated before the delivery withholds the backend. The
        // delivery that lands after the gate ran covers it, and only a reload
        // loads it.
        platform::set_delivery(Delivery::Pending);
        let withheld = gate_at_reload(&kafka(), &LicenseRuntimeState::default())
            .expect("withheld, not refused");
        let runtime = LicenseRuntimeState::from(&withheld);
        assert_eq!(runtime.withheld, ["dev.mcpg.backend.kafka"]);
        assert!(!runtime.is_behind_platform());
        platform::set_delivery(delivered(&cloud_licence("enterprise", "acme"), "acme"));
        assert!(runtime.is_behind_platform());
        assert!(
            runtime.regate(&kafka()).expect("covered"),
            "a reload loads it"
        );

        // A delivery that covers nothing more asks for no reload.
        platform::set_delivery(delivered("", "acme"));
        assert!(runtime.is_behind_platform());
        assert!(!runtime.regate(&kafka()).expect("still withheld"));

        // A runtime that loaded it keeps it while the licence covers it, and
        // gating again catches it up.
        platform::set_delivery(delivered(&cloud_licence("enterprise", "acme"), "acme"));
        let loaded = LicenseRuntimeState::from(&outcome);
        platform::set_bound_plugins(Some(["dev.mcpg.backend.kafka".to_owned()].into()));
        assert!(loaded.is_behind_platform());
        assert!(!loaded.regate(&kafka()).expect("keeps what it loaded"));
        let regated = gate_at_reload(&kafka(), &loaded).expect("keeps what it loaded");
        assert!(!LicenseRuntimeState::from(&regated).is_behind_platform());

        // A delivery that no longer covers it asks for the reload that
        // withholds it.
        platform::set_delivery(delivered("", "acme"));
        assert!(loaded.regate(&kafka()).expect("withheld, not refused"));

        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::Pending);
    }

    /// A restart whose delivery in hand is the one read back at start, and
    /// lower than the config needs, waits for the control plane's own word
    /// instead of refusing at once, and boots on it.
    #[tokio::test]
    async fn a_restart_waits_for_a_fresh_delivery_when_the_cached_one_is_lower() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_bound_plugins(None);
        platform::seed_from_cache(
            Some(delivered_as(&signed_license("pro"), "acme", Origin::Cached)),
            None,
        );
        let started = std::time::Instant::now();
        let deliver = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            platform::set_delivery(delivered_as(
                &signed_license("enterprise"),
                "acme",
                Origin::Unproven,
            ));
        });
        let outcome = gate_at_boot(&cfg)
            .await
            .expect("boots once the control plane answers");
        deliver.await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(outcome.status.plan, "enterprise");
        assert!(outcome.held.is_empty() && outcome.withheld.is_empty());

        platform::clear_seed();
        platform::set_delivery(Delivery::Pending);
    }

    /// Past its wait, a restart withholds what it can and loads and holds the
    /// rest, as the running gateway before it did, instead of refusing the
    /// boot and crash-looping until a delivery covers it. A first boot still
    /// refuses.
    #[tokio::test]
    async fn a_restart_past_its_wait_holds_what_it_cannot_withhold() {
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis", "dev.mcpg.backend.kafka"],
            ATTACHED,
        );
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_bound_plugins(None);
        let pro = signed_license("pro");
        platform::seed_from_cache(Some(delivered_as(&pro, "acme", Origin::Cached)), None);
        let outcome = gate_at_boot_within(&cfg, Duration::from_millis(200))
            .await
            .expect("boots, holding");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert_eq!(outcome.held, ["dev.mcpg.cluster.redis"]);
        assert!(outcome.tool_hold().is_some());

        // The control plane's own word that the plan is still lower boots
        // the same way, without waiting out the rest of the wait.
        platform::set_delivery(delivered_as(&pro, "acme", Origin::Unproven));
        let started = std::time::Instant::now();
        let outcome = gate_at_boot_within(&cfg, Duration::from_secs(10))
            .await
            .expect("boots, holding");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome.held, ["dev.mcpg.cluster.redis"]);

        platform::clear_seed();
        let refusal = gate_at_boot_within(&cfg, Duration::from_millis(200))
            .await
            .expect_err("a first boot refuses");
        assert!(
            format!("{refusal:#}").contains("cluster.redis"),
            "{refusal:#}"
        );

        platform::set_delivery(Delivery::Pending);
    }

    /// A restart whose bound set, read back at start, leaves out a gated
    /// plugin the config names — one the control plane took back from the
    /// pod before — takes it back again instead of refusing the boot, once
    /// the wait for a fresh set is over or the control plane sends the same
    /// set; a fresh set that binds it loads it.
    #[tokio::test]
    async fn a_restart_takes_back_what_the_cached_bound_set_leaves_out() {
        let cfg = config_with_plugins(
            &["dev.mcpg.cluster.redis", "dev.mcpg.backend.kafka"],
            ATTACHED,
        );
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        let enterprise = delivered_as(&signed_license("enterprise"), "acme", Origin::Cached);
        let narrow: BTreeSet<String> = ["dev.mcpg.backend.http".to_owned()].into();
        let seed =
            || platform::seed_from_cache(Some(enterprise.clone()), Some(Some(narrow.clone())));

        seed();
        let outcome = gate_at_boot_within(&cfg, Duration::from_millis(200))
            .await
            .expect("boots, holding");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert_eq!(outcome.held, ["dev.mcpg.cluster.redis"]);
        assert_eq!(outcome.hold, Some(HoldReason::NotBound));

        seed();
        let same = narrow.clone();
        let resend = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            platform::set_bound_plugins(Some(same));
        });
        let started = std::time::Instant::now();
        let outcome = gate_at_boot_within(&cfg, Duration::from_secs(10))
            .await
            .expect("boots, holding");
        resend.await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "woken by the resend"
        );
        assert_eq!(outcome.held, ["dev.mcpg.cluster.redis"]);

        seed();
        let resend = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            platform::set_bound_plugins(Some(
                ["dev.mcpg.cluster.redis", "dev.mcpg.backend.kafka"]
                    .map(str::to_owned)
                    .into(),
            ));
        });
        let outcome = gate_at_boot_within(&cfg, Duration::from_secs(10))
            .await
            .expect("boots with both");
        resend.await.unwrap();
        assert!(outcome.held.is_empty() && outcome.withheld.is_empty());

        platform::clear_seed();
        platform::set_bound_plugins(None);
        platform::set_delivery(Delivery::Pending);
    }

    /// Whether a gateway is gated as attached is fixed when its process
    /// starts. A reload that drops `gateway.control_plane` leaves a gateway
    /// that booted attached on the delivered licence, its own `license:`
    /// block still ignored; one that adds it leaves a standalone gateway on
    /// its own licence.
    #[tokio::test]
    async fn attachment_is_fixed_when_the_process_starts() {
        let attached = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        if !platform::attached(&attached) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_bound_plugins(None);
        platform::set_delivery(delivered("", "acme"));
        let boot = gate_at_boot(&attached).await.expect("withheld");
        assert_eq!(boot.status.withheld, ["dev.mcpg.backend.kafka"]);
        let running = LicenseRuntimeState::from(&boot);

        let detached =
            config_with_plugins(&["dev.mcpg.backend.kafka"], &license_yaml_for("enterprise"));
        let reload = gate_at_reload(&detached, &running).expect("still withheld");
        assert_eq!(reload.status.source, LicenseSource::Platform);
        assert_eq!(reload.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert!(LicenseRuntimeState::from(&reload).attached == Some(true));

        let standalone = config_with_plugins(&[], "");
        let running = LicenseRuntimeState::from(&gate_at_boot(&standalone).await.unwrap());
        let refusal = gate_at_reload(&attached, &running)
            .expect_err("a standalone gateway has no licence for it");
        assert!(
            format!("{refusal:#}").contains("backend.kafka"),
            "{refusal:#}"
        );

        platform::set_delivery(Delivery::Pending);
    }

    /// A customer's own control plane relays its self-host licence.
    #[test]
    fn a_relayed_self_host_licence_admits() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let token = signed_license("enterprise");
        for origin in [Origin::Unproven, Origin::Cached] {
            evaluate(
                &cfg,
                &inputs(
                    &delivered_as(&token, "default", origin),
                    &BTreeSet::new(),
                    now(),
                ),
            )
            .unwrap_or_else(|e| panic!("{origin:?}: {e}"));
        }
    }

    /// A cloud licence counts only on a delivery a platform key proved for
    /// this process, so a control plane without one, such as a customer's
    /// own, cannot make it count: one relayed without a proof, or read back
    /// from the state directory with no proof that still holds, waits like a
    /// licence that does not verify.
    #[test]
    fn a_cloud_licence_counts_only_on_a_delivery_mcpg_cloud_proved() {
        let token = cloud_licence("enterprise", "acme");
        let redis = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let kafka = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        for (origin, says) in [
            (Origin::Unproven, "no proof that mcpg.cloud sent it"),
            (Origin::Cached, "read back from this gateway's state"),
        ] {
            let delivery = delivered_as(&token, "acme", origin);
            let refusal = evaluate(&redis, &inputs(&delivery, &BTreeSet::new(), now()))
                .expect_err("a coordinator waits");
            assert!(refusal.waits_for_delivery(), "{refusal}");
            assert!(refusal.to_string().contains(says), "{refusal}");
            let outcome = evaluate(&kafka, &inputs(&delivery, &BTreeSet::new(), now()))
                .expect("withheld, not refused");
            assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
            assert_eq!(outcome.status.plan, "community");
        }
        let outcome = evaluate(
            &redis,
            &inputs(&delivered(&token, "acme"), &BTreeSet::new(), now()),
        )
        .expect("proven, it covers the coordinator");
        assert_eq!(outcome.status.plan, "enterprise");
    }

    const UID: &str = "gw-1";

    fn channel(nonce: &str) -> ChannelBinding<'_> {
        ChannelBinding {
            nonce,
            instance_uid: UID,
        }
    }

    fn platform_key() -> ed25519_dalek::SigningKey {
        test_override::trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Production)
    }

    /// A cloud licence that arrives without a proof that verifies is counted,
    /// by why, and comes back as the refusal the gateway reports, with the
    /// refused proof's `kid`; a licence that needs no proof, or none at all,
    /// is neither.
    #[test]
    fn an_unproven_cloud_licence_is_counted_and_reported() {
        use mcpg_control_plane_license::delivery::{new_nonce, test_proof};
        let token = cloud_licence("enterprise", "acme");
        let nonce = new_nonce();
        let key = platform_key();
        let proof = test_proof::sign(
            &test_proof::claims(&nonce, UID, "acme", &token, now()),
            &key,
        );
        // Only the licence series: a warning the call logs may count itself
        // on the same recorder.
        let counted = |license: &str, proof: &str, nonce: &str| {
            let recorder = Gauges::default();
            let judged = metrics::with_local_recorder(&recorder, || {
                judge_delivery(license, "acme", proof, channel(nonce), now())
            });
            let seen: Vec<String> = recorder
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m.starts_with("mcpg_license_"))
                .cloned()
                .collect();
            (judged, seen)
        };

        let (judged, seen) = counted(&token, "", &nonce);
        assert_eq!(judged.origin, Origin::Unproven);
        assert_eq!(
            seen,
            ["mcpg_license_unproven_deliveries_total{reason=no_proof}"]
        );
        assert_eq!(
            judged.refusal,
            Some(DeliveryRefusal {
                reason: "no_proof",
                proof_kid: String::new(),
            })
        );
        let (judged, seen) = counted(&token, &proof, &new_nonce());
        assert_eq!(judged.origin, Origin::Unproven);
        assert_eq!(
            seen,
            ["mcpg_license_unproven_deliveries_total{reason=proof_refused}"]
        );
        assert_eq!(
            judged.refusal,
            Some(DeliveryRefusal {
                reason: "proof_refused",
                proof_kid: mcpg_control_plane_license::trust::thumbprint_kid(&key.verifying_key()),
            })
        );

        let mut self_host = claims_for("enterprise", AUDIENCE_GATEWAY);
        self_host.tenant_slug = "acme".into();
        let self_host =
            test_override::issue(IssuerRole::SelfHost, KeyEnvironment::Production, &self_host);
        for (license, proof, nonce) in [
            (token.as_str(), proof.as_str(), nonce.as_str()),
            (self_host.as_str(), "", nonce.as_str()),
            ("", "", nonce.as_str()),
        ] {
            let (judged, seen) = counted(license, proof, nonce);
            assert!(seen.is_empty(), "{seen:?}");
            assert_eq!(judged.refusal, None);
        }
    }

    /// A booting gateway whose Channel the control plane refuses because
    /// another Channel of its instance holds the slot waits for its licence
    /// past its own wait, until that wait has run again after the slot frees.
    #[tokio::test]
    async fn a_boot_whose_channel_slot_is_held_waits_for_the_slot_to_free() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_delivery(Delivery::Pending);
        let started = std::time::Instant::now();
        platform::slot_held(Duration::from_millis(400));
        let token = cloud_licence("enterprise", "acme");
        let deliver = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(600)).await;
            platform::set_delivery(delivered(&token, "acme"));
        });
        let outcome = gate_at_boot_within(&cfg, Duration::from_millis(300)).await;
        deliver.await.unwrap();
        platform::clear_slot();
        platform::set_delivery(Delivery::Pending);
        let outcome = outcome.expect("boots on the licence the freed slot's Channel brings");
        assert!(started.elapsed() >= Duration::from_millis(600));
        assert_eq!(outcome.status.plan, "enterprise");
    }

    /// The boot wait runs again from when the slot frees, and stops at most
    /// the longest silence a control plane allows past its own wait.
    #[test]
    fn the_boot_deadline_covers_a_held_slot() {
        let started = tokio::time::Instant::now();
        let wait = LICENSE_WAIT;
        assert_eq!(boot_deadline(started, wait, None), started + wait);
        let soon = started + Duration::from_secs(1);
        assert_eq!(
            boot_deadline(started, wait, Some(soon)),
            soon + wait,
            "the wait runs again from the slot"
        );
        assert_eq!(
            boot_deadline(started, wait, Some(started - Duration::from_secs(60))),
            started + wait,
            "a slot freed long ago shortens nothing"
        );
        assert_eq!(
            boot_deadline(started, wait, Some(started + Duration::from_secs(3600))),
            started + wait + MAX_SLOT_WAIT
        );
    }

    /// A proof makes a delivery mcpg.cloud's only for the Channel that sent
    /// the nonce it names, the instance that Channel is authenticated as, the
    /// org and the licence it vouches for, and only when a platform key
    /// signed it.
    #[test]
    fn a_delivery_is_proven_only_by_a_proof_for_its_own_channel() {
        use mcpg_control_plane_license::delivery::{new_nonce, test_proof};
        let key = platform_key();
        let token = cloud_licence("enterprise", "acme");
        let nonce = new_nonce();
        let proof = test_proof::sign(
            &test_proof::claims(&nonce, UID, "acme", &token, now()),
            &key,
        );
        assert_eq!(
            origin_of(&token, "acme", &proof, channel(&nonce), now()),
            Origin::Proven
        );
        let community = test_proof::sign(&test_proof::claims(&nonce, UID, "acme", "", now()), &key);
        assert_eq!(
            origin_of("", "acme", &community, channel(&nonce), now()),
            Origin::Proven
        );

        assert_eq!(
            origin_of(&token, "acme", &proof, channel(&new_nonce()), now()),
            Origin::Unproven,
            "a proof replayed onto another Channel"
        );
        let other_instance = ChannelBinding {
            nonce: &nonce,
            instance_uid: "gw-2",
        };
        assert_eq!(
            origin_of(&token, "acme", &proof, other_instance, now()),
            Origin::Unproven,
            "a proof relayed to another instance"
        );
        assert_eq!(
            origin_of(&token, "acme", "", channel(&nonce), now()),
            Origin::Unproven
        );
        assert_eq!(
            origin_of(
                &cloud_licence("enterprise", "acme"),
                "acme",
                &proof,
                channel(&nonce),
                now()
            ),
            Origin::Unproven,
            "a proof for another licence"
        );
        let globex = cloud_licence("enterprise", "globex");
        let for_acme = test_proof::sign(
            &test_proof::claims(&nonce, UID, "acme", &globex, now()),
            &key,
        );
        assert_eq!(
            origin_of(&globex, "globex", &for_acme, channel(&nonce), now()),
            Origin::Unproven,
            "a proof for another org"
        );
        for role in [IssuerRole::Cloud, IssuerRole::SelfHost] {
            let licence_key = test_override::trusted_signing_key(role, KeyEnvironment::Production);
            let forged = test_proof::sign(
                &test_proof::claims(&nonce, UID, "acme", &token, now()),
                &licence_key,
            );
            assert_eq!(
                origin_of(&token, "acme", &forged, channel(&nonce), now()),
                Origin::Unproven,
                "only a platform key signs a proof, not a {role:?} key"
            );
        }
    }

    /// A staging platform key vouches only for a non-production licence, so
    /// the key staging control planes hold cannot pass off a production one.
    #[test]
    fn a_staging_platform_key_proves_no_production_licence() {
        use mcpg_control_plane_license::delivery::{new_nonce, test_proof};
        let staging =
            test_override::trusted_signing_key(IssuerRole::Platform, KeyEnvironment::Staging);
        let nonce = new_nonce();
        let prove = |token: &str| {
            test_proof::sign(
                &test_proof::claims(&nonce, UID, "acme", token, now()),
                &staging,
            )
        };
        let production = cloud_licence("enterprise", "acme");
        assert_eq!(
            origin_of(
                &production,
                "acme",
                &prove(&production),
                channel(&nonce),
                now()
            ),
            Origin::Unproven
        );
        let mut claims = claims_for("enterprise", "mcpg-cp");
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = "acme".into();
        claims.non_production = true;
        let marked = test_override::issue(IssuerRole::Cloud, KeyEnvironment::Staging, &claims);
        assert_eq!(
            origin_of(&marked, "acme", &prove(&marked), channel(&nonce), now()),
            Origin::Proven
        );
    }

    /// A restart counts the cached licence mcpg.cloud proved, on the proof
    /// kept with it, for a day after that proof was signed and not past the
    /// licence's own grace; with no proof, or one that no longer holds, it
    /// waits like any cached delivery.
    #[test]
    fn a_cached_proven_licence_counts_for_a_day_after_its_proof() {
        use mcpg_control_plane_license::delivery::{LAST_KNOWN_GOOD_SECS, new_nonce, test_proof};
        let key = platform_key();
        let token = cloud_licence("enterprise", "acme");
        let nonce = new_nonce();
        let signed_at = now() - 3_600;
        let proof = test_proof::sign(
            &test_proof::claims(&nonce, UID, "acme", &token, signed_at),
            &key,
        );
        let origin = cached_origin_of(&token, "acme", &proof, channel(&nonce), now());
        let until = signed_at + LAST_KNOWN_GOOD_SECS;
        assert_eq!(origin, Origin::CachedProven { until });
        assert_eq!(
            cached_origin_of(&token, "acme", &proof, channel(&nonce), until),
            Origin::Cached,
            "a day after the proof"
        );
        assert_eq!(
            cached_origin_of(&token, "acme", "", channel(&nonce), now()),
            Origin::Cached
        );
        let other_instance = ChannelBinding {
            nonce: &nonce,
            instance_uid: "gw-2",
        };
        assert_eq!(
            cached_origin_of(&token, "acme", &proof, other_instance, now()),
            Origin::Cached,
            "a state directory copied to another instance"
        );

        let redis = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let cached = delivered_as(&token, "acme", origin);
        let outcome = evaluate(&redis, &inputs(&cached, &BTreeSet::new(), now()))
            .expect("it counts while the proof holds");
        assert_eq!(outcome.status.plan, "enterprise");
        assert_eq!(outcome.counts_until, Some(until));
        let runtime = LicenseRuntimeState::from(&outcome);
        assert_eq!(runtime.lapses_at, Some(until), "gated again when it ends");
        let refusal = evaluate(&redis, &inputs(&cached, &BTreeSet::new(), until))
            .expect_err("past the day it waits");
        assert!(refusal.waits_for_delivery(), "{refusal}");

        // The licence's own expiry and grace still bound it.
        let mut lapsed_claims = claims_for("enterprise", "mcpg-cp");
        lapsed_claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        lapsed_claims.tenant_slug = "acme".into();
        lapsed_claims.exp = now() - 30 * 86_400;
        let lapsed_cloud = test_override::issue(
            IssuerRole::Cloud,
            KeyEnvironment::Production,
            &lapsed_claims,
        );
        let lapsed_proof = test_proof::sign(
            &test_proof::claims(&nonce, UID, "acme", &lapsed_cloud, now()),
            &key,
        );
        let origin = cached_origin_of(&lapsed_cloud, "acme", &lapsed_proof, channel(&nonce), now());
        let refusal = evaluate(
            &redis,
            &inputs(
                &delivered_as(&lapsed_cloud, "acme", origin),
                &BTreeSet::new(),
                now(),
            ),
        )
        .expect_err("a lapsed licence counts for nothing");
        assert!(refusal.to_string().contains("grace"), "{refusal}");
    }

    /// The control plane's own word replaces the cached licence a restart
    /// counts on its proof: one that cannot prove the delivery drops it at
    /// once, even for the same licence, and a proven one takes over.
    #[cfg(feature = "cp-attached")]
    #[tokio::test]
    async fn an_unproven_live_delivery_drops_a_cached_proven_licence_at_once() {
        use mcpg_control_plane_license::delivery::LAST_KNOWN_GOOD_SECS;
        let _platform = platform::test_lock().await;
        let token = cloud_licence("enterprise", "acme");
        let cached = delivered_as(
            &token,
            "acme",
            Origin::CachedProven {
                until: now() + LAST_KNOWN_GOOD_SECS,
            },
        );
        platform::set_delivery(cached.clone());
        assert!(platform::receive_delivery(delivered_as(
            &token,
            "acme",
            Origin::Unproven
        )));
        let redis = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        let now_gating = platform::delivery_for(&redis);
        assert_eq!(*now_gating, delivered_as(&token, "acme", Origin::Unproven));
        evaluate(&redis, &inputs(&now_gating, &BTreeSet::new(), now()))
            .expect_err("the cloud licence no longer counts");

        platform::set_delivery(cached);
        assert!(platform::receive_delivery(delivered(&token, "acme")));
        assert_eq!(
            *platform::delivery_for(&redis),
            delivered(&token, "acme"),
            "a proven delivery takes over"
        );
        platform::set_delivery(Delivery::Pending);
    }

    /// A proven delivery of a licence this release cannot verify — signed
    /// with a cloud key it does not embed yet, or damaged — leaves a restart
    /// on the cached licence it counts, as a running gateway keeps the one it
    /// holds, until the day that cached proof holds ends.
    #[cfg(feature = "cp-attached")]
    #[tokio::test]
    async fn a_proven_licence_that_does_not_verify_leaves_the_cached_one() {
        use mcpg_control_plane_license::delivery::LAST_KNOWN_GOOD_SECS;
        let _platform = platform::test_lock().await;
        let token = cloud_licence("enterprise", "acme");
        let cached = delivered_as(
            &token,
            "acme",
            Origin::CachedProven {
                until: now() + LAST_KNOWN_GOOD_SECS,
            },
        );
        platform::set_delivery(cached.clone());
        assert!(!platform::receive_delivery(delivered(
            "unverifiable.cloud.licence",
            "acme"
        )));
        let redis = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        assert_eq!(*platform::delivery_for(&redis), cached);
        let outcome = evaluate(
            &redis,
            &inputs(&platform::delivery_for(&redis), &BTreeSet::new(), now()),
        )
        .expect("the cached licence still counts");
        assert_eq!(outcome.status.plan, "enterprise");

        assert!(
            platform::receive_delivery(delivered_as(&token, "acme", Origin::Unproven)),
            "an unproven delivery still drops it"
        );
        platform::set_delivery(Delivery::Pending);
    }

    /// A restart that kept a proven delivery boots on it at once, without
    /// waiting for the control plane, while that proof holds.
    #[tokio::test]
    async fn a_restart_boots_on_the_cached_proven_licence_without_waiting() {
        use mcpg_control_plane_license::delivery::LAST_KNOWN_GOOD_SECS;
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], ATTACHED);
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_bound_plugins(None);
        platform::seed_from_cache(
            Some(delivered_as(
                &cloud_licence("enterprise", "acme"),
                "acme",
                Origin::CachedProven {
                    until: now() + LAST_KNOWN_GOOD_SECS,
                },
            )),
            None,
        );
        let started = std::time::Instant::now();
        let outcome = gate_at_boot_within(&cfg, Duration::from_secs(10))
            .await
            .expect("boots on it");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome.status.plan, "enterprise");
        assert!(outcome.held.is_empty());

        platform::clear_seed();
        platform::set_delivery(Delivery::Pending);
    }

    /// A gateway mcpg.cloud delivered to keeps gating on that delivery when
    /// a later one arrives with a cloud licence and no proof.
    #[cfg(feature = "cp-attached")]
    #[tokio::test]
    async fn an_unproven_cloud_licence_never_replaces_a_proven_delivery() {
        let _platform = platform::test_lock().await;
        let enterprise = cloud_licence("enterprise", "acme");
        platform::set_delivery(delivered(&enterprise, "acme"));
        let copy = cloud_licence("enterprise", "acme");
        assert!(!platform::receive_delivery(delivered_as(
            &copy,
            "acme",
            Origin::Unproven
        )));
        assert_eq!(
            *platform::delivery_for(&config_with_plugins(&[], ATTACHED)),
            delivered(&enterprise, "acme")
        );
        // The platform's word that the org holds none applies, proven or not.
        assert!(platform::receive_delivery(delivered_as(
            "",
            "acme",
            Origin::Unproven
        )));
        platform::set_delivery(Delivery::Pending);
    }

    /// A control plane that re-sends the licence mcpg.cloud already proved to
    /// this process without a proof, with the word that its refresh is
    /// failing, leaves the licence proven, so the gateway warns instead of
    /// dropping the word, and the org holding none stays mcpg.cloud's word,
    /// with the block ignored.
    #[cfg(feature = "cp-attached")]
    #[tokio::test]
    async fn a_proven_licence_sent_again_without_a_proof_stays_proven() {
        let _platform = platform::test_lock().await;
        let failing = |delivery: Delivery| match delivery {
            Delivery::Delivered {
                license_jwt,
                org_slug,
                origin,
                ..
            } => Delivery::Delivered {
                license_jwt,
                org_slug,
                origin,
                refresh_failing: true,
            },
            other => other,
        };
        let cfg = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let enterprise = cloud_licence("enterprise", "acme");
        platform::set_delivery(delivered(&enterprise, "acme"));
        assert!(platform::receive_delivery(failing(delivered_as(
            &enterprise,
            "acme",
            Origin::Unproven
        ))));
        let now_gating = platform::delivery_for(&cfg);
        assert_eq!(*now_gating, failing(delivered(&enterprise, "acme")));
        let status = evaluate(&cfg, &inputs(&now_gating, &BTreeSet::new(), now()))
            .expect("still covered")
            .status;
        assert_eq!((status.state, status.refresh_failing), ("expiring", true));

        // Another licence still needs a proof of its own.
        assert!(!platform::receive_delivery(delivered_as(
            &cloud_licence("enterprise", "acme"),
            "acme",
            Origin::Unproven
        )));

        let declared = config_with_plugins(
            &["dev.mcpg.backend.kafka"],
            &format!("{ATTACHED}license:\n  non_production_use: true\n"),
        );
        platform::set_delivery(delivered("", "acme"));
        platform::receive_delivery(delivered_as("", "acme", Origin::Unproven));
        let outcome = evaluate(
            &declared,
            &inputs(&platform::delivery_for(&declared), &BTreeSet::new(), now()),
        )
        .expect("withheld, not refused");
        assert_eq!(outcome.status.source, LicenseSource::Platform);
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);

        platform::set_delivery(Delivery::Pending);
    }

    /// An attached gateway ignores its own `license:` block only when
    /// mcpg.cloud proved the delivery: then the platform's licence is its
    /// only licence. Under a customer's own control plane, before any
    /// delivery, and on a delivery read back at start, the block is its
    /// licence, a token or the non-production declaration alike.
    #[test]
    fn an_attached_gateway_honours_its_block_unless_mcpg_cloud_delivers() {
        let licensed_block = config_with_plugins(
            &["dev.mcpg.cluster.redis"],
            &format!("{ATTACHED}{}", license_yaml_for("enterprise")),
        );
        let community = || delivered_as("", "acme", Origin::Unproven);
        for delivery in [
            Delivery::Pending,
            community(),
            delivered_as("", "acme", Origin::Cached),
            delivered_as(&signed_license("pro"), "acme", Origin::Unproven),
        ] {
            let outcome = evaluate(&licensed_block, &inputs(&delivery, &BTreeSet::new(), now()))
                .unwrap_or_else(|e| panic!("{delivery:?}: the block covers it: {e}"));
            assert_eq!(outcome.status.source, LicenseSource::LicenseBlock);
            assert_eq!(outcome.status.plan, "enterprise");
        }

        let declared = config_with_plugins(
            &["dev.mcpg.backend.kafka"],
            &format!("{ATTACHED}license:\n  non_production_use: true\n"),
        );
        let outcome = evaluate(&declared, &inputs(&community(), &BTreeSet::new(), now()))
            .expect("the declaration loads it");
        assert!(outcome.status.withheld.is_empty());
        assert_eq!(
            outcome.status.source,
            LicenseSource::NonProductionDeclaration
        );
        assert!(outcome.status.non_production);

        // mcpg.cloud's word, even that the org holds no licence, is the
        // gateway's only licence.
        let proven_community = delivered("", "acme");
        let refusal = evaluate(
            &licensed_block,
            &inputs(&proven_community, &BTreeSet::new(), now()),
        )
        .expect_err("the block grants nothing");
        assert!(refusal.to_string().contains("cluster.redis"), "{refusal}");
        let outcome = evaluate(
            &declared,
            &inputs(&proven_community, &BTreeSet::new(), now()),
        )
        .expect("withheld, not refused");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert_eq!(outcome.status.source, LicenseSource::Platform);
        assert!(!outcome.status.non_production);
        let enterprise = cloud_licence("enterprise", "acme");
        let outcome = evaluate(
            &licensed_block,
            &inputs(&delivered(&enterprise, "acme"), &BTreeSet::new(), now()),
        )
        .expect("the delivered licence covers it");
        assert_eq!(outcome.status.source, LicenseSource::Platform);
        let garbage =
            config_with_plugins(&[], &format!("{ATTACHED}license:\n  token: not-a-jwt\n"));
        let outcome = evaluate(
            &garbage,
            &inputs(&proven_community, &BTreeSet::new(), now()),
        )
        .expect("an ignored block is never verified");
        assert_eq!(outcome.status.source, LicenseSource::Platform);
    }

    /// Until the control plane's word to this process shows it is not
    /// mcpg.cloud — before its first delivery, on the delivery read back at
    /// start, or on a cloud licence sent without a proof — a proven delivery
    /// may still replace an attached gateway's `license:` block. The block
    /// admits what it covers, but what it does not cover, or a block that
    /// does not verify, waits for that delivery instead of refusing the boot,
    /// and a restart lands holding it. A customer control plane's own word
    /// leaves the block the licence, as on a standalone gateway.
    #[test]
    fn an_attached_block_never_refuses_what_a_proven_delivery_may_cover() {
        let cloud = cloud_licence("enterprise", "acme");
        let lower = config_with_plugins(
            &["dev.mcpg.cluster.redis"],
            &format!("{ATTACHED}{}", license_yaml_for("pro")),
        );
        let broken = config_with_plugins(
            &["dev.mcpg.cluster.redis"],
            &format!("{ATTACHED}license:\n  token: not-a-jwt\n"),
        );
        let undecided = [
            Delivery::Pending,
            delivered_as(&cloud, "acme", Origin::Cached),
            delivered_as(&cloud, "acme", Origin::Unproven),
        ];
        let nothing_loaded = BTreeSet::new();
        for delivery in &undecided {
            for cfg in [&lower, &broken] {
                let refusal = evaluate(cfg, &inputs(delivery, &nothing_loaded, now()))
                    .expect_err("a coordinator waits");
                assert!(refusal.waits_for_delivery(), "{delivery:?}: {refusal}");
                let restart = GateInputs {
                    restart: true,
                    ..inputs(delivery, &nothing_loaded, now())
                };
                let outcome = evaluate(cfg, &restart)
                    .unwrap_or_else(|e| panic!("{delivery:?}: a restart lands: {e}"));
                assert_eq!(outcome.held, ["dev.mcpg.cluster.redis"], "{delivery:?}");
            }
        }
        for cfg in [&lower, &broken] {
            let outcome = evaluate(
                cfg,
                &inputs(&delivered(&cloud, "acme"), &BTreeSet::new(), now()),
            )
            .expect("the proven licence covers it");
            assert_eq!(outcome.status.source, LicenseSource::Platform);
        }

        for delivery in [
            delivered_as("", "acme", Origin::Unproven),
            delivered_as(&signed_license("enterprise"), "acme", Origin::Unproven),
        ] {
            let refusal = evaluate(&lower, &inputs(&delivery, &BTreeSet::new(), now()))
                .expect_err("the block is the licence");
            assert!(!refusal.waits_for_delivery(), "{delivery:?}: {refusal}");
            assert!(evaluate(&broken, &inputs(&delivery, &BTreeSet::new(), now())).is_err());
        }
    }

    /// A standalone gateway's own `license:` block is its licence.
    #[test]
    fn a_standalone_gateway_runs_on_its_license_block() {
        let cfg = config_with_plugins(&["dev.mcpg.cluster.redis"], &license_yaml_for("enterprise"));
        let outcome = evaluate(
            &cfg,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("the local licence covers it");
        assert_eq!(outcome.status.source, LicenseSource::LicenseBlock);
    }

    /// A delivery that drops the org's plan takes away what the running
    /// gateway loaded under the plan it had, as a boot on it would: backends
    /// and tool gates are withheld, and a withheld tool gate refuses every
    /// call in its place.
    #[test]
    fn a_lower_delivery_withholds_what_the_running_gateway_loaded() {
        let cfg = config_with_plugins(
            &["dev.mcpg.backend.kafka", "dev.mcpg.tool-gate.dlp"],
            ATTACHED,
        );
        let enterprise = cloud_licence("enterprise", "acme");
        let running = evaluate(
            &cfg,
            &inputs(&delivered(&enterprise, "acme"), &BTreeSet::new(), now()),
        )
        .expect("enterprise covers both")
        .admitted;
        assert_eq!(running.len(), 2);

        let outcome = evaluate(&cfg, &inputs(&delivered("", "acme"), &running, now()))
            .expect("withheld, not refused");
        assert_eq!(
            outcome.status.withheld,
            ["dev.mcpg.backend.kafka", "dev.mcpg.tool-gate.dlp"]
        );
        assert!(outcome.admitted.is_empty(), "{:?}", outcome.admitted);
        let hold = outcome
            .tool_hold()
            .expect("the withheld tool gate holds calls");
        assert!(
            hold.contains("dev.mcpg.tool-gate.dlp") && hold.contains("`community` licence"),
            "{hold}"
        );

        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&enterprise, "acme"), &BTreeSet::new(), now()),
        )
        .expect("covered again");
        assert!(outcome.withheld.is_empty() && outcome.tool_hold().is_none());
    }

    /// What a running gateway cannot run without — a coordinator, an
    /// authorization-server surface — stays loaded when a delivery no longer
    /// covers it, and the gateway serves no call until one does, as a boot
    /// that waits for it serves nothing. A config that newly adds such an
    /// item is refused as at boot.
    #[test]
    fn a_lower_delivery_holds_every_call_for_what_cannot_be_withheld() {
        let cfg = interactive_login_config(&format!(
            "{ATTACHED}plugins:\n  - id: dev.mcpg.cluster.redis\n    class: cluster\n    \
             source: {{ path: /tmp/x.so }}\n"
        ));
        let enterprise = cloud_licence("enterprise", "acme");
        let running = evaluate(
            &cfg,
            &inputs(&delivered(&enterprise, "acme"), &BTreeSet::new(), now()),
        )
        .expect("enterprise covers both")
        .admitted;

        let community = delivered("", "acme");
        let outcome =
            evaluate(&cfg, &inputs(&community, &running, now())).expect("held, not refused");
        assert!(outcome.withheld.is_empty());
        assert_eq!(outcome.admitted, running, "held items stay loaded");
        assert_eq!(
            outcome.status.held,
            [
                "dev.mcpg.cluster.redis",
                "governance.access.authorization_server.trusted_idps[`https://acme.okta.com`].login",
                "governance.access.authorization_server.interactive",
            ]
        );
        let hold = outcome.tool_hold().expect("held items hold every call");
        assert!(
            hold.contains("dev.mcpg.cluster.redis") && hold.contains("cannot run without"),
            "{hold}"
        );
        let health = serde_json::to_value(&outcome.status).unwrap();
        assert_eq!(health["held"].as_array().map(Vec::len), Some(3));

        evaluate(&cfg, &inputs(&community, &BTreeSet::new(), now()))
            .expect_err("a config that adds them is refused");
    }

    /// MCP Events webhook delivery is a licensed surface on every plan. A
    /// delivered licence without the feature holds it: the runtime state
    /// carries why, and a later licence with it releases the hold.
    #[test]
    fn webhook_delivery_is_held_without_its_licence_feature() {
        let events = |webhook: &str| {
            serde_yaml::from_str::<AppConfig>(&format!(
                "{ATTACHED}mcp:\n  configurations:\n    events:\n      enabled: true\n{webhook}"
            ))
            .expect("test config parses")
        };
        let off = events("      webhook: { enabled: false }\n");
        assert!(licensed_config_surfaces(&off).is_empty());
        let cfg = events("");
        assert_eq!(
            licensed_config_surfaces(&cfg),
            vec![(FEATURE_EVENTS_WEBHOOKS, EVENTS_WEBHOOK_SURFACE.to_owned())]
        );
        let standalone: AppConfig =
            serde_yaml::from_str("mcp:\n  configurations:\n    events:\n      enabled: true\n")
                .expect("test config parses");
        enforce_license_gate(&standalone).expect("the community tier grants it");

        let pro = delivered(&cloud_licence("pro", "acme"), "acme");
        let running = evaluate(&cfg, &inputs(&pro, &BTreeSet::new(), now()))
            .expect("pro covers it")
            .admitted;
        let mut claims = claims_for("pro", "mcpg-cp");
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = "acme".into();
        claims.features.retain(|f| f != FEATURE_EVENTS_WEBHOOKS);
        let without = delivered(
            &test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims),
            "acme",
        );
        let outcome = evaluate(&cfg, &inputs(&without, &running, now())).expect("held");
        assert_eq!(outcome.status.held, [EVENTS_WEBHOOK_SURFACE]);
        let state = LicenseRuntimeState::from(&outcome);
        assert!(
            state
                .events_hold
                .as_deref()
                .is_some_and(|why| why.contains("held"))
        );

        let again = evaluate(&cfg, &inputs(&pro, &running, now())).expect("covered again");
        assert!(LicenseRuntimeState::from(&again).events_hold.is_none());
    }

    /// A plugin set the control plane binds that leaves out a gated plugin
    /// the running gateway loaded or withholds takes it back as a lower
    /// licence would: withheld when the gateway can run without it, else
    /// held, on every gate from then on. So such a set never stops a lower
    /// licence from applying. A boot, or a config that adds the plugin, is
    /// still refused.
    #[test]
    fn a_bound_set_that_leaves_out_what_runs_takes_it_back() {
        let cfg = config_with_plugins(
            &[
                "dev.mcpg.backend.kafka",
                "dev.mcpg.cluster.redis",
                "dev.mcpg.tool-gate.dlp",
            ],
            ATTACHED,
        );
        let enterprise = delivered(&cloud_licence("enterprise", "acme"), "acme");
        let community = delivered("", "acme");
        let running = LicenseRuntimeState::from(
            &evaluate(&cfg, &inputs(&enterprise, &BTreeSet::new(), now()))
                .expect("enterprise covers them"),
        );
        let bound: BTreeSet<String> = ["dev.mcpg.tool-gate.dlp".to_owned()].into();
        let gate = |delivery: &Delivery, running: &LicenseRuntimeState| {
            evaluate(
                &cfg,
                &GateInputs {
                    delivery,
                    bound_plugins: Some(&bound),
                    admitted: &running.admitted,
                    withheld: &running.withheld,
                    restart: false,
                    now: now(),
                },
            )
        };

        let outcome = gate(&enterprise, &running).expect("taken back, not refused");
        let taken_back = LicenseRuntimeState::from(&outcome);
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert_eq!(outcome.status.held, ["dev.mcpg.cluster.redis"]);
        assert_eq!(outcome.hold, Some(HoldReason::NotBound));
        let hold = outcome
            .tool_hold()
            .expect("the held coordinator holds calls");
        assert!(
            hold.contains("dev.mcpg.cluster.redis") && hold.contains("plugin set"),
            "{hold}"
        );

        let outcome = gate(&community, &running).expect("the lower licence applies");
        assert_eq!(
            outcome.status.withheld,
            ["dev.mcpg.backend.kafka", "dev.mcpg.tool-gate.dlp"]
        );
        let why = outcome.hold.as_ref().map(HoldReason::describe).unwrap();
        assert!(
            why.contains("`community` licence") && why.contains("plugin set"),
            "{why}"
        );

        assert_eq!(
            gate(&enterprise, &taken_back)
                .expect("what the set took back stays withheld")
                .status
                .withheld,
            ["dev.mcpg.backend.kafka"]
        );
        assert_eq!(
            gate(&community, &taken_back)
                .expect("a lower licence still applies")
                .status
                .withheld,
            ["dev.mcpg.backend.kafka", "dev.mcpg.tool-gate.dlp"]
        );
        let lower = LicenseRuntimeState::from(
            &evaluate(&cfg, &inputs(&community, &running.admitted, now()))
                .expect("withheld, not refused"),
        );
        assert_eq!(
            gate(&community, &lower)
                .expect("what a lower licence withheld stays withheld when the set leaves it out")
                .status
                .withheld,
            ["dev.mcpg.backend.kafka", "dev.mcpg.tool-gate.dlp"]
        );

        let refusal = gate(&enterprise, &LicenseRuntimeState::default())
            .expect_err("not running: refused")
            .to_string();
        assert!(
            refusal.contains("`dev.mcpg.backend.kafka` is not in the plugin set"),
            "{refusal}"
        );
    }

    /// The licence status names what the running gateway runs on: a regate
    /// whose answer only a reload applies publishes nothing, so a reload that
    /// fails leaves it true, while one that changes nothing loaded publishes
    /// at once.
    #[tokio::test]
    async fn a_regate_publishes_the_status_only_when_no_reload_is_needed() {
        with_reported_status(regate_publishes_only_without_a_reload()).await;
    }

    async fn regate_publishes_only_without_a_reload() {
        use super::reported_status as current_status;
        let kafka = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        if !platform::attached(&kafka) {
            return;
        }
        let _platform = platform::test_lock().await;
        platform::set_bound_plugins(None);
        platform::set_delivery(delivered(&cloud_licence("enterprise", "acme"), "acme"));
        let running = gate_at_reload(&kafka, &LicenseRuntimeState::default()).expect("covered");
        report(&running);
        let runtime = LicenseRuntimeState::from(&running);

        platform::set_delivery(delivered("", "acme"));
        assert!(runtime.regate(&kafka).expect("withheld, not refused"));
        let status = current_status().expect("published");
        assert!(
            status.withheld.is_empty() && status.plan == "enterprise",
            "the backend still runs until a reload withholds it: {status:?}"
        );

        let plain = config_with_plugins(&[], ATTACHED);
        let idle = LicenseRuntimeState::from(
            &gate_at_reload(&plain, &LicenseRuntimeState::default()).unwrap(),
        );
        platform::set_delivery(delivered(&cloud_licence("team", "acme"), "acme"));
        assert!(!idle.regate(&plain).expect("nothing gated"));
        assert_eq!(current_status().expect("published").plan, "team");

        platform::set_delivery(Delivery::Pending);
    }

    /// A delivered licence that does not verify — a key this release does not
    /// embed, another org's licence, a damaged token — says nothing about the
    /// org's plan, so it never replaces a delivery that verifies. It does
    /// replace a pending or unverifiable one, and no licence replaces any.
    #[tokio::test]
    async fn an_unverifiable_delivery_never_replaces_a_verified_one() {
        let cfg = config_with_plugins(&[], ATTACHED);
        if !platform::attached(&cfg) {
            return;
        }
        let _platform = platform::test_lock().await;
        let enterprise = delivered(&cloud_licence("enterprise", "acme"), "acme");
        let damaged = delivered("not-a-jwt", "acme");
        let foreign = delivered(&cloud_licence("enterprise", "globex"), "acme");

        platform::set_delivery(Delivery::Pending);
        assert!(platform::receive_delivery(damaged.clone()));
        assert_eq!(*platform::delivery_for(&cfg), damaged);
        assert!(platform::receive_delivery(enterprise.clone()));
        for unverifiable in [damaged, foreign] {
            assert!(!platform::receive_delivery(unverifiable));
            assert_eq!(*platform::delivery_for(&cfg), enterprise);
        }
        let community = delivered("", "acme");
        assert!(platform::receive_delivery(community.clone()));
        assert_eq!(*platform::delivery_for(&cfg), community);

        platform::set_delivery(Delivery::Pending);
    }

    /// A runtime that loaded gated items under a delivered licence knows when
    /// that licence's grace ends; one that loaded none, a lapsed one and a
    /// standalone gateway's licence block have nothing to gate again for.
    #[test]
    fn a_runtime_knows_when_its_delivered_licence_lapses() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let mut claims = claims_for("enterprise", "mcpg-cp");
        claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
        claims.tenant_slug = "acme".into();
        let cloud = |claims: &LicenseClaims| {
            test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, claims)
        };
        let runtime = |cfg: &AppConfig, delivery: &Delivery| {
            let outcome = evaluate(cfg, &inputs(delivery, &BTreeSet::new(), now())).unwrap();
            LicenseRuntimeState::from(&outcome).lapses_at
        };

        let current = delivered(&cloud(&claims), "acme");
        assert_eq!(runtime(&cfg, &current), Some(claims.exp + 7 * DAY));
        assert_eq!(runtime(&config_with_plugins(&[], ATTACHED), &current), None);
        assert_eq!(runtime(&cfg, &delivered("", "acme")), None);

        claims.exp = now() - 8 * DAY;
        claims.nbf = claims.exp - 30 * DAY;
        claims.iat = claims.nbf;
        assert_eq!(runtime(&cfg, &delivered(&cloud(&claims), "acme")), None);

        let standalone =
            config_with_plugins(&["dev.mcpg.backend.kafka"], &license_yaml_for("enterprise"));
        assert_eq!(runtime(&standalone, &Delivery::Standalone), None);
    }

    /// A delivered cloud licence keeps its plan seven days past `exp` while
    /// its refresh fails, then lapses; a self-host licence a customer's own
    /// control plane relays keeps the self-host fourteen.
    #[test]
    fn a_delivered_cloud_licence_keeps_its_plan_seven_days_past_expiry() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let cloud_expired = |days_ago: i64| {
            let mut claims = claims_for("enterprise", "mcpg-cp");
            claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
            claims.tenant_slug = "acme".into();
            claims.exp = now() - days_ago * DAY;
            claims.nbf = claims.exp - 30 * DAY;
            claims.iat = claims.nbf;
            test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims)
        };

        let token = cloud_expired(5);
        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&token, "acme"), &BTreeSet::new(), now()),
        )
        .expect("in grace");
        assert_eq!(outcome.status.state, "grace");
        assert!(outcome.withheld.is_empty());
        assert_eq!(
            outcome.status.grace_ends_at.unwrap() - outcome.status.expires_at.unwrap(),
            chrono::Duration::days(7)
        );

        let token = cloud_expired(8);
        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&token, "acme"), &BTreeSet::new(), now()),
        )
        .expect("withheld, not refused");
        assert_eq!(outcome.status.state, "lapsed");
        assert_eq!(outcome.status.withheld, ["dev.mcpg.backend.kafka"]);
        assert!(
            outcome
                .hold
                .as_ref()
                .unwrap()
                .describe()
                .contains("7-day grace period"),
            "{:?}",
            outcome.hold
        );

        let mut relayed = claims_for("enterprise", AUDIENCE_GATEWAY);
        relayed.exp = now() - 8 * DAY;
        relayed.nbf = relayed.exp - 30 * DAY;
        relayed.iat = relayed.nbf;
        let relayed =
            test_override::issue(IssuerRole::SelfHost, KeyEnvironment::Production, &relayed);
        let outcome = evaluate(
            &cfg,
            &inputs(&delivered(&relayed, "default"), &BTreeSet::new(), now()),
        )
        .expect("in the self-host grace");
        assert_eq!(outcome.status.state, "grace");
    }

    /// An mcpg.cloud licence expires a few days past the end of each billing
    /// month and is renewed before then, so it is not `expiring`, and the
    /// daily reminder stays quiet, until the control plane reports that its
    /// refresh is failing or the licence is past `exp`. A self-host licence
    /// still warns from 30 days out.
    #[test]
    fn a_cloud_licence_warns_only_when_its_refresh_fails_or_it_expired() {
        let cfg = config_with_plugins(&["dev.mcpg.backend.kafka"], ATTACHED);
        let cloud = |exp: i64| {
            let mut claims = claims_for("enterprise", "mcpg-cp");
            claims.aud.push(AUDIENCE_GATEWAY_MANAGED.into());
            claims.tenant_slug = "acme".into();
            claims.exp = exp;
            claims.nbf = exp.min(now()) - 30 * DAY;
            claims.iat = claims.nbf;
            test_override::issue(IssuerRole::Cloud, KeyEnvironment::Production, &claims)
        };
        let status = |token: &str, refresh_failing: bool| {
            let delivery = Delivery::Delivered {
                license_jwt: token.into(),
                org_slug: "acme".into(),
                origin: Origin::Proven,
                refresh_failing,
            };
            evaluate(&cfg, &inputs(&delivery, &BTreeSet::new(), now()))
                .expect("covered")
                .status
        };

        let in_ten_days = cloud(now() + 10 * DAY);
        let renewing = status(&in_ten_days, false);
        assert_eq!(renewing.state, "current");
        assert!(!renewing.refresh_failing);
        assert!(!needs_reminder(&renewing));

        let failing = status(&in_ten_days, true);
        assert_eq!(failing.state, "expiring");
        assert!(failing.refresh_failing);
        assert!(needs_reminder(&failing));
        let far = status(&cloud(now() + 60 * DAY), true);
        assert_eq!(far.state, "expiring", "a failing refresh warns at once");

        let expired = status(&cloud(now() - DAY), false);
        assert_eq!(expired.state, "grace");
        assert!(needs_reminder(&expired));

        let self_host = config_with_plugins(
            &["dev.mcpg.backend.kafka"],
            &license_expiring_at("enterprise", now() + 10 * DAY),
        );
        let outcome = evaluate(
            &self_host,
            &inputs(&Delivery::Standalone, &BTreeSet::new(), now()),
        )
        .expect("covered");
        assert_eq!(outcome.status.state, "expiring");
        assert!(needs_reminder(&outcome.status));
    }

    /// The bound set governs the gated plugins. A free plugin, or the
    /// coordinator the platform adds to a multi-replica gateway, is in no
    /// tenant's set, so binding a set never stops a gateway over one.
    #[test]
    fn gated_plugins_outside_the_bound_set_are_refused() {
        let token = cloud_licence("enterprise", "acme");
        let delivery = delivered(&token, "acme");
        let cfg = config_with_plugins(
            &[
                "dev.mcpg.backend.http",
                license::PLATFORM_COORDINATOR_PLUGIN,
                "dev.mcpg.cluster.redis",
                "dev.mcpg.backend.kafka",
            ],
            ATTACHED,
        );
        let gate = |bound: &[&str]| {
            let bound: BTreeSet<String> = bound.iter().map(|id| (*id).to_owned()).collect();
            evaluate(
                &cfg,
                &GateInputs {
                    delivery: &delivery,
                    bound_plugins: Some(&bound),
                    admitted: &BTreeSet::new(),
                    withheld: &[],
                    restart: false,
                    now: now(),
                },
            )
        };

        let err = gate(&["dev.mcpg.cluster.redis"]).unwrap_err().to_string();
        assert!(
            err.contains("`dev.mcpg.backend.kafka` is not in the plugin set"),
            "{err}"
        );
        for bound_or_exempt in ["backend.http", "cluster.nats", "cluster.redis"] {
            assert!(!err.contains(bound_or_exempt), "{bound_or_exempt}: {err}");
        }

        gate(&["dev.mcpg.cluster.redis", "dev.mcpg.backend.kafka"])
            .expect("every gated plugin is bound");
    }

    /// An authorization server with interactive sign-in, parsed without
    /// validation: the gate reads the blocks, not their contents.
    fn interactive_login_config(extra: &str) -> AppConfig {
        let yaml = format!(
            "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
             signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
             - issuer: https://acme.okta.com\n          login:\n            client_id: agent\n        \
             - issuer: https://other.example.com\n      interactive: {{}}\n{extra}"
        );
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    /// Interactive sign-in is enterprise-only: the community envelope and a
    /// team license refuse to boot with it and name both blocks and the
    /// feature; an enterprise license or the non-production grant admit it.
    #[test]
    fn interactive_login_needs_its_license_feature() {
        let surfaces = licensed_config_surfaces(&interactive_login_config(""));
        assert_eq!(
            surfaces,
            vec![
                (
                    FEATURE_INTERACTIVE_LOGIN,
                    "governance.access.authorization_server.trusted_idps[`https://acme.okta.com`].login"
                        .to_owned()
                ),
                (
                    FEATURE_INTERACTIVE_LOGIN,
                    "governance.access.authorization_server.interactive".to_owned()
                ),
            ]
        );

        for license_yaml in [String::new(), license_yaml_for("team")] {
            let err = enforce_license_gate(&interactive_login_config(&license_yaml))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("2 configured item(s)")
                    && err.contains("trusted_idps[`https://acme.okta.com`].login requires")
                    && err.contains("authorization_server.interactive requires")
                    && err.contains("`sso.interactive_login`")
                    && err.contains("non_production_use"),
                "{err}"
            );
        }
        enforce_license_gate(&interactive_login_config(&license_yaml_for("enterprise")))
            .expect("enterprise licenses interactive login");
        enforce_license_gate(&interactive_login_config(
            "license:\n  non_production_use: true\n",
        ))
        .expect("the non-production grant admits interactive login");
    }

    /// The platform's render stamp (a control plane block plus placement
    /// provenance) is not a licence: the surfaces are checked against the
    /// licence the platform delivers, and wait for it.
    #[test]
    fn a_platform_render_stamp_does_not_skip_the_surface_gate() {
        let rendered = interactive_login_config(&format!("{ATTACHED}{PROVENANCE}"));
        enforce_license_gate(&rendered).expect_err("a stamp alone licenses nothing");

        let refusal = evaluate(
            &rendered,
            &inputs(&Delivery::Pending, &BTreeSet::new(), now()),
        )
        .unwrap_err();
        assert!(refusal.waits_for_delivery(), "{refusal}");
        assert!(
            refusal.to_string().contains("`sso.interactive_login`"),
            "{refusal}"
        );

        let enterprise = cloud_licence("enterprise", "acme");
        evaluate(
            &rendered,
            &inputs(&delivered(&enterprise, "acme"), &BTreeSet::new(), now()),
        )
        .expect("the delivered enterprise licence admits interactive login");
        let team = cloud_licence("team", "acme");
        let refusal = evaluate(
            &rendered,
            &inputs(&delivered(&team, "acme"), &BTreeSet::new(), now()),
        )
        .unwrap_err();
        assert!(
            refusal
                .to_string()
                .contains("`team` licence does not include"),
            "{refusal}"
        );
    }

    /// An EMA-only authorization server with `extra` under it, parsed without
    /// validation: the gate reads the blocks, not their contents.
    fn authorization_server_config(server_extra: &str, extra: &str) -> AppConfig {
        let yaml = format!(
            "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
             signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
             - issuer: https://acme.okta.com\n{server_extra}{extra}"
        );
        serde_yaml::from_str(&yaml).expect("test config parses")
    }

    const DPOP_ON: &str = "      dpop:\n        enabled: true\n        required: true\n";
    const DETAILS_ON: &str = "      authorization_details:\n        types:\n          \
                              - type: mcp_tool\n            actions: [\"tools/call\"]\n";

    fn constrained_tokens_config(extra: &str) -> AppConfig {
        authorization_server_config(&format!("{DPOP_ON}{DETAILS_ON}"), extra)
    }

    /// DPoP and rich authorization requests are enterprise-only: the
    /// community envelope and a team license refuse to boot with either
    /// turned on and name the block, the feature and the plan; an enterprise
    /// license or the non-production grant admit both.
    #[test]
    fn dpop_and_rich_authorization_need_their_license_features() {
        assert_eq!(
            licensed_config_surfaces(&constrained_tokens_config("")),
            vec![
                (
                    FEATURE_DPOP,
                    "governance.access.authorization_server.dpop".to_owned()
                ),
                (
                    FEATURE_RICH_AUTHORIZATION,
                    "governance.access.authorization_server.authorization_details".to_owned()
                ),
            ]
        );

        for (plan, license_yaml) in [
            ("community", String::new()),
            ("team", license_yaml_for("team")),
        ] {
            let err = enforce_license_gate(&constrained_tokens_config(&license_yaml))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("plan `{plan}`"))
                    && err.contains("2 configured item(s)")
                    && err.contains(
                        "governance.access.authorization_server.dpop requires the `oauth.dpop` \
                         plan feature"
                    )
                    && err.contains(
                        "governance.access.authorization_server.authorization_details requires \
                         the `oauth.rich_authorization` plan feature"
                    )
                    && err.contains("non_production_use"),
                "{err}"
            );

            let dpop_only = authorization_server_config(DPOP_ON, &license_yaml);
            let err = enforce_license_gate(&dpop_only).unwrap_err().to_string();
            assert!(
                err.contains("1 configured item(s)")
                    && err.contains("`oauth.dpop`")
                    && !err.contains("oauth.rich_authorization"),
                "{err}"
            );
            let details_only = authorization_server_config(DETAILS_ON, &license_yaml);
            let err = enforce_license_gate(&details_only).unwrap_err().to_string();
            assert!(
                err.contains("1 configured item(s)")
                    && err.contains("`oauth.rich_authorization`")
                    && !err.contains("oauth.dpop"),
                "{err}"
            );
        }
        enforce_license_gate(&constrained_tokens_config(&license_yaml_for("enterprise")))
            .expect("enterprise licenses DPoP and rich authorization requests");
        enforce_license_gate(&constrained_tokens_config(
            "license:\n  non_production_use: true\n",
        ))
        .expect("the non-production grant admits DPoP and rich authorization requests");
    }

    /// Every gated block of one server is named in one refusal, whichever
    /// feature it needs.
    #[test]
    fn one_refusal_names_every_authorization_server_feature() {
        let every = format!("{DPOP_ON}{DETAILS_ON}      interactive: {{}}\n");
        let err = enforce_license_gate(&authorization_server_config(&every, ""))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("3 configured item(s)")
                && err.contains("`sso.interactive_login`")
                && err.contains("`oauth.dpop`")
                && err.contains("`oauth.rich_authorization`"),
            "{err}"
        );
    }

    /// A present block that leaves its surface off needs no feature: `dpop`
    /// with `enabled: false` whatever its other keys, and
    /// `authorization_details` without a type.
    #[test]
    fn disabled_dpop_and_authorization_details_blocks_need_no_feature() {
        for server_extra in [
            "      dpop:\n        enabled: false\n        nonce: always\n        \
             proof_max_age_secs: 30\n        allowed_algs: [ES256]\n",
            "      dpop: {}\n",
            "      authorization_details:\n        max_entries: 8\n",
            "      authorization_details:\n        types: []\n        max_entries: 4\n",
            "      dpop:\n        enabled: false\n      authorization_details:\n        types: []\n",
        ] {
            let cfg = authorization_server_config(server_extra, "");
            assert!(licensed_config_surfaces(&cfg).is_empty(), "{server_extra}");
            enforce_license_gate(&cfg).expect(server_extra);
        }
    }

    /// An EMA-only server (no login block, no interactive block) needs no
    /// feature and boots on the community envelope.
    #[test]
    fn an_ema_only_authorization_server_needs_no_feature() {
        let yaml = "governance:\n  access:\n    authorization_server:\n      issuer: https://mcp.example.com\n      \
                    signing_secret: ema-signing-secret-0123456789abcdef\n      trusted_idps:\n        \
                    - issuer: https://acme.okta.com\n";
        let cfg: AppConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(licensed_config_surfaces(&cfg).is_empty());
        enforce_license_gate(&cfg).expect("EMA alone is not gated");
    }

    #[test]
    fn the_wait_shape_follows_what_the_plugin_is() {
        for (id, shape) in [
            ("dev.mcpg.payment.x402", WaitShape::WithholdAndHoldTools),
            ("dev.mcpg.tool-gate.dlp", WaitShape::WithholdAndHoldTools),
            ("dev.mcpg.guardrails", WaitShape::WithholdAndHoldTools),
            (
                "dev.mcpg.tool-gate-slack-approval",
                WaitShape::WithholdAndHoldTools,
            ),
            ("dev.mcpg.backend.kafka", WaitShape::Withhold),
            ("dev.mcpg.credential.aws-sts", WaitShape::Withhold),
            ("dev.mcpg.secret.vault", WaitShape::Withhold),
            ("dev.mcpg.cluster.nats", WaitShape::MustWait),
            ("dev.mcpg.policy.cedar", WaitShape::MustWait),
            ("dev.mcpg.identity.saml", WaitShape::MustWait),
            ("dev.mcpg.audit.s3-worm", WaitShape::MustWait),
        ] {
            assert_eq!(wait_shape(id), shape, "{id}");
        }
    }
}
