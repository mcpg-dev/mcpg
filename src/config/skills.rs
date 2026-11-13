//! `mcp.skills:` — Agent Skills served over the SEP-2640 Skills extension.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// `mcp.skills:` — Agent Skills the gateway serves to clients over the MCP
/// Skills extension (`io.modelcontextprotocol/skills`).
///
/// A skill is a folder with a `SKILL.md` at its root, whose YAML frontmatter
/// holds at least `name` (equal to the folder's name) and `description`.
/// Each folder of a source that holds a `SKILL.md` is one skill, served as
/// `skill://<prefix>/<folder path>/SKILL.md` together with every other file
/// of that folder. Clients find the skills with `skills/list` and
/// `skills/get`, read each file with `resources/read`, and list a folder
/// with `resources/directory/read`.
///
/// The files are read once, when the gateway starts or reloads its config,
/// and served from memory, so each file's digest always matches its bytes.
/// Reads go through the same access rules as any other resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillsConfig {
    /// The folders skills are served from. Empty (the default) serves no
    /// skills and does not declare the extension.
    #[serde(default)]
    pub sources: Vec<SkillSourceConfig>,

    /// Serve `resources/directory/read` and declare `directoryRead: true`.
    /// Default `true`.
    #[serde(default = "default_true")]
    pub directory_read: bool,

    /// Also list each skill's `SKILL.md` in `resources/list`, for clients
    /// that do not speak the extension. Default `true`.
    #[serde(default = "default_true")]
    pub list_as_resources: bool,

    /// Who may list and read the skills: the same block a binding takes.
    /// Applies to every skill file and folder, beside any
    /// `governance.policy.tool_access` rule filed under its URI. Unset
    /// `minimum_trust` takes `default_minimum_trust`.
    #[serde(default, skip_serializing_if = "is_default_governance")]
    pub governance: mcpg_expr::governance::BackendGovernanceConfig,
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            directory_read: true,
            list_as_resources: true,
            governance: Default::default(),
        }
    }
}

fn is_default_governance(governance: &mcpg_expr::governance::BackendGovernanceConfig) -> bool {
    *governance == Default::default()
}

/// One folder of skills under `mcp.skills.sources`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillSourceConfig {
    /// The folder. A relative path resolves against the folder of the last
    /// config file. A config that comes from no file (inline, from a URL,
    /// pushed by a control plane) must give an absolute path; a relative
    /// one is refused at boot. The gateway logs the absolute folder of each
    /// source. Files and folders whose names start with `.` are not served.
    /// Symbolic links are followed (a Kubernetes ConfigMap mount is made of
    /// them); a broken link or a link loop is refused.
    pub path: String,

    /// A path the skills of this source are served under, such as
    /// `acme/billing`: its folder `refunds/` is then
    /// `skill://acme/billing/refunds/SKILL.md`. Segments are separated by
    /// `/` and use letters, digits, `-`, `.`, `_` and `~`. Unset serves the
    /// skills at the root of the `skill://` namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

fn default_true() -> bool {
    true
}

impl SkillsConfig {
    /// Whether this is the default block, which leaves the field out of a
    /// serialized config.
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether any source is configured.
    pub fn is_enabled(&self) -> bool {
        !self.sources.is_empty()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.governance.validate("mcp.skills")?;
        for (index, source) in self.sources.iter().enumerate() {
            if source.path.trim().is_empty() {
                anyhow::bail!("mcp.skills.sources[{index}].path must not be empty");
            }
            if let Some(prefix) = &source.prefix {
                validate_prefix(prefix)
                    .map_err(|e| anyhow::anyhow!("mcp.skills.sources[{index}].prefix: {e}"))?;
            }
        }
        Ok(())
    }
}

/// A prefix is one or more `/`-separated segments of URI-unreserved
/// characters, none of them `.` or `..`.
fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        anyhow::bail!("must not be empty; leave it unset to serve at the namespace root");
    }
    for segment in prefix.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            anyhow::bail!("`{prefix}` has an empty, `.` or `..` segment");
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            anyhow::bail!(
                "`{prefix}` holds a character other than letters, digits, `-`, `.`, `_` and `~`"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(path: &str, prefix: Option<&str>) -> SkillSourceConfig {
        SkillSourceConfig {
            path: path.to_owned(),
            prefix: prefix.map(str::to_owned),
        }
    }

    #[test]
    fn the_default_serves_nothing_and_is_left_out_of_a_serialized_config() {
        let config: SkillsConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(config, SkillsConfig::default());
        assert!(config.is_default());
        assert!(!config.is_enabled());
        assert!(config.directory_read && config.list_as_resources);
    }

    #[test]
    fn a_source_parses_with_its_prefix() {
        let config: SkillsConfig = serde_yaml::from_str(
            "sources: [{ path: skills, prefix: acme/billing }]\ndirectory_read: false",
        )
        .unwrap();
        assert!(config.is_enabled());
        assert_eq!(config.sources, vec![source("skills", Some("acme/billing"))]);
        assert!(!config.directory_read);
        config.validate().unwrap();
    }

    #[test]
    fn a_bad_source_is_refused() {
        for (bad, why) in [
            (source(" ", None), "path must not be empty"),
            (source("s", Some("")), "must not be empty"),
            (source("s", Some("a//b")), "empty, `.` or `..`"),
            (source("s", Some("a/../b")), "empty, `.` or `..`"),
            (source("s", Some("a b")), "a character other than"),
        ] {
            let config = SkillsConfig {
                sources: vec![bad],
                ..SkillsConfig::default()
            };
            let error = config.validate().unwrap_err().to_string();
            assert!(error.contains(why), "{error}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused() {
        assert!(serde_yaml::from_str::<SkillsConfig>("source: []").is_err());
    }
}
