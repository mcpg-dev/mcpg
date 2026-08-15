//! Top-level `debug:` block — operator-defined diagnostic tools
//! (probe + JSON-call + overview prompt/resource).
//!
//! The master switch lives at `feature_flags.debug_tools_enabled`.
//! When that flag is `false`, every field
//! in this block is ignored AND the `mcpg.debug.*` tools are
//! stripped from the capability registry. The block remains
//! defaulted-off; flip the feature flag on AND populate the
//! profiles to expose the tools.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_COMMAND_PROFILE: &str = "default_command_probe";
pub(crate) const DEFAULT_NETWORK_PROFILE: &str = "default_network_probe";

/// Top-level `debug:` block — diagnostic tools surface only.
/// The master switch lives at `feature_flags.debug_tools_enabled`.
/// When that flag is `false`, every
/// field below is ignored AND the `mcpg.debug.*` tools are
/// stripped from the capability registry regardless of
/// `tools.exposure`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugConfig {
    /// Operator-defined diagnostic tools surfaced as MCP tools
    /// when `feature_flags.debug_tools_enabled: true`. See
    /// [`DebugToolsConfig`] for the surface.
    #[serde(default)]
    pub tools: DebugToolsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugToolsConfig {
    #[serde(default)]
    pub command_profiles: BTreeMap<String, DebugCommandToolConfig>,
    #[serde(default)]
    pub network_profiles: BTreeMap<String, DebugNetworkToolConfig>,
    #[serde(default)]
    pub bindings: DebugToolBackendsConfig,
    #[serde(default)]
    pub exposure: DebugToolExposureConfig,
}

impl Default for DebugToolsConfig {
    fn default() -> Self {
        let mut command_profiles = BTreeMap::new();
        command_profiles.insert(
            DEFAULT_COMMAND_PROFILE.to_owned(),
            DebugCommandToolConfig::default(),
        );
        let mut network_profiles = BTreeMap::new();
        network_profiles.insert(
            DEFAULT_NETWORK_PROFILE.to_owned(),
            DebugNetworkToolConfig::default(),
        );

        Self {
            command_profiles,
            network_profiles,
            bindings: DebugToolBackendsConfig::default(),
            exposure: DebugToolExposureConfig::default(),
        }
    }
}

impl DebugToolsConfig {
    pub(crate) fn validate(&self, debug_enabled: bool) -> Result<()> {
        if !debug_enabled {
            return Ok(());
        }
        if !self.command_profiles.contains_key(DEFAULT_COMMAND_PROFILE) {
            return Err(anyhow::anyhow!(
                "debug.tools.command_profiles must contain '{}' when debug is enabled",
                DEFAULT_COMMAND_PROFILE
            ));
        }
        if !self.network_profiles.contains_key(DEFAULT_NETWORK_PROFILE) {
            return Err(anyhow::anyhow!(
                "debug.tools.network_profiles must contain '{}' when debug is enabled",
                DEFAULT_NETWORK_PROFILE
            ));
        }
        if !self.exposure.command_probe
            && !self.exposure.network_probe
            && !self.exposure.network_json_call
            && !self.exposure.operational_overview_prompt
            && !self.exposure.runtime_overview_resource
        {
            return Err(anyhow::anyhow!(
                "debug.tools.exposure must enable at least one built-in debug capability when debug is enabled"
            ));
        }
        self.bindings.validate(self)?;
        for (name, profile) in &self.command_profiles {
            if name.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "debug.tools.command_profiles keys must not be empty"
                ));
            }
            if profile.command.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "debug.tools.command_profiles.{}.command must not be empty when debug is enabled",
                    name
                ));
            }
            if profile.timeout_ms == 0 {
                return Err(anyhow::anyhow!(
                    "debug.tools.command_profiles.{}.timeout_ms must be greater than 0 when debug is enabled",
                    name
                ));
            }
            if profile.max_output_bytes == 0 {
                return Err(anyhow::anyhow!(
                    "debug.tools.command_profiles.{}.max_output_bytes must be greater than 0 when debug is enabled",
                    name
                ));
            }
        }
        for (name, profile) in &self.network_profiles {
            if name.trim().is_empty() {
                return Err(anyhow::anyhow!(
                    "debug.tools.network_profiles keys must not be empty"
                ));
            }
            if !profile.url.starts_with("http://") {
                return Err(anyhow::anyhow!(
                    "debug.tools.network_profiles.{}.url must start with 'http://' when debug is enabled",
                    name
                ));
            }
            if profile.timeout_ms == 0 {
                return Err(anyhow::anyhow!(
                    "debug.tools.network_profiles.{}.timeout_ms must be greater than 0 when debug is enabled",
                    name
                ));
            }
            if profile.max_response_bytes == 0 {
                return Err(anyhow::anyhow!(
                    "debug.tools.network_profiles.{}.max_response_bytes must be greater than 0 when debug is enabled",
                    name
                ));
            }
            if profile.expected_status_codes.is_empty() {
                return Err(anyhow::anyhow!(
                    "debug.tools.network_profiles.{}.expected_status_codes must not be empty when debug is enabled",
                    name
                ));
            }
            for status_code in &profile.expected_status_codes {
                if !(100..=599).contains(status_code) {
                    return Err(anyhow::anyhow!(
                        "debug.tools.network_profiles.{}.expected_status_codes entries must be valid HTTP status codes when debug is enabled",
                        name
                    ));
                }
            }
            for (header_name, header_value) in &profile.headers {
                if header_name.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "debug.tools.network_profiles.{}.headers keys must not be empty when debug is enabled",
                        name
                    ));
                }
                if header_name.contains(['\r', '\n']) {
                    return Err(anyhow::anyhow!(
                        "debug.tools.network_profiles.{}.headers keys must not contain CR or LF characters when debug is enabled",
                        name
                    ));
                }
                if header_value.contains(['\r', '\n']) {
                    return Err(anyhow::anyhow!(
                        "debug.tools.network_profiles.{}.headers values must not contain CR or LF characters when debug is enabled",
                        name
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugToolExposureConfig {
    #[serde(default = "crate::config::default_true")]
    pub command_probe: bool,
    #[serde(default = "crate::config::default_true")]
    pub network_probe: bool,
    #[serde(default = "crate::config::default_false")]
    pub network_json_call: bool,
    #[serde(default = "crate::config::default_true")]
    pub operational_overview_prompt: bool,
    #[serde(default = "crate::config::default_true")]
    pub runtime_overview_resource: bool,
}

impl Default for DebugToolExposureConfig {
    fn default() -> Self {
        Self {
            command_probe: crate::config::default_true(),
            network_probe: crate::config::default_true(),
            network_json_call: crate::config::default_false(),
            operational_overview_prompt: crate::config::default_true(),
            runtime_overview_resource: crate::config::default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugToolBackendsConfig {
    #[serde(default = "default_command_probe_binding")]
    pub command_probe_profile: String,
    #[serde(default = "default_network_probe_binding")]
    pub network_probe_profile: String,
    #[serde(default = "default_network_json_call_binding")]
    pub network_json_call_profile: String,
}

impl Default for DebugToolBackendsConfig {
    fn default() -> Self {
        Self {
            command_probe_profile: default_command_probe_binding(),
            network_probe_profile: default_network_probe_binding(),
            network_json_call_profile: default_network_json_call_binding(),
        }
    }
}

impl DebugToolBackendsConfig {
    fn validate(&self, debug_tools: &DebugToolsConfig) -> Result<()> {
        if self.command_probe_profile.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.command_probe_profile must not be empty when debug is enabled"
            ));
        }
        if self.network_probe_profile.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.network_probe_profile must not be empty when debug is enabled"
            ));
        }
        if self.network_json_call_profile.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.network_json_call_profile must not be empty when debug is enabled"
            ));
        }
        if !debug_tools
            .command_profiles
            .contains_key(&self.command_probe_profile)
        {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.command_probe_profile must reference an existing command profile"
            ));
        }
        if !debug_tools
            .network_profiles
            .contains_key(&self.network_probe_profile)
        {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.network_probe_profile must reference an existing network profile"
            ));
        }
        if !debug_tools
            .network_profiles
            .contains_key(&self.network_json_call_profile)
        {
            return Err(anyhow::anyhow!(
                "debug.tools.bindings.network_json_call_profile must reference an existing network profile"
            ));
        }
        Ok(())
    }
}

fn default_command_probe_binding() -> String {
    DEFAULT_COMMAND_PROFILE.to_owned()
}

fn default_network_probe_binding() -> String {
    DEFAULT_NETWORK_PROFILE.to_owned()
}

fn default_network_json_call_binding() -> String {
    DEFAULT_NETWORK_PROFILE.to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugCommandToolConfig {
    #[serde(default = "default_debug_command")]
    pub command: String,
    #[serde(default = "default_debug_command_args")]
    pub args: Vec<String>,
    #[serde(default = "default_debug_command_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_debug_command_max_output_bytes")]
    pub max_output_bytes: usize,
}

impl Default for DebugCommandToolConfig {
    fn default() -> Self {
        Self {
            command: default_debug_command(),
            args: default_debug_command_args(),
            timeout_ms: default_debug_command_timeout_ms(),
            max_output_bytes: default_debug_command_max_output_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugNetworkToolConfig {
    #[serde(default = "default_debug_network_url")]
    pub url: String,
    #[serde(default = "default_debug_network_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_debug_network_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_debug_network_expected_status_codes")]
    pub expected_status_codes: Vec<u16>,
    #[serde(default)]
    pub require_json_response: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

impl Default for DebugNetworkToolConfig {
    fn default() -> Self {
        Self {
            url: default_debug_network_url(),
            timeout_ms: default_debug_network_timeout_ms(),
            max_response_bytes: default_debug_network_max_response_bytes(),
            expected_status_codes: default_debug_network_expected_status_codes(),
            require_json_response: false,
            headers: BTreeMap::new(),
        }
    }
}

fn default_debug_command() -> String {
    "printf".to_owned()
}

fn default_debug_command_args() -> Vec<String> {
    vec!["mcpg-debug-command\n".to_owned()]
}

fn default_debug_command_timeout_ms() -> u64 {
    2_000
}

fn default_debug_command_max_output_bytes() -> usize {
    4_096
}

fn default_debug_network_url() -> String {
    "http://127.0.0.1:8787/health".to_owned()
}

fn default_debug_network_timeout_ms() -> u64 {
    2_000
}

fn default_debug_network_max_response_bytes() -> usize {
    4_096
}

fn default_debug_network_expected_status_codes() -> Vec<u16> {
    vec![200]
}
