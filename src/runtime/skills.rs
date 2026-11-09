//! The skills a gateway serves over the SEP-2640 Skills extension.
//!
//! [`SkillCatalog::load`] reads every configured source once and holds the
//! bytes, so what `resources/read` returns is exactly what the digests in
//! `skills/list` and `skills/get` describe. A config reload builds a new
//! catalog; a source that changes on disk is served as it was read until
//! then.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::config::skills::SkillsConfig;
use crate::protocol::shared::skills::{
    DIRECTORY_MIME_TYPE, MAX_BYTES_PER_SKILL, MAX_RESOURCES_PER_SKILL, SKILL_FILE, SKILL_MIME_TYPE,
    SKILL_SCHEME, SkillEntry, SkillFile, SkillResources, format_digest, is_valid_skill_name,
};

/// Longest `description` the Agent Skills specification allows.
const MAX_DESCRIPTION_CHARS: usize = 1024;

/// The wire a Skills request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillsWire {
    /// `2025-11-25`: session-bound, no `resultType`.
    Legacy,
    /// `2026-07-28`: stateless, results carry `resultType`.
    Modern,
}

impl SkillsWire {
    /// The HTTP status of a `-32601` on this wire.
    pub fn not_found_status(self) -> u16 {
        match self {
            Self::Legacy => 200,
            Self::Modern => 404,
        }
    }
}

/// One served skill.
#[derive(Debug, Clone)]
pub struct Skill {
    /// The entry `skills/list` and `skills/get` return.
    pub entry: SkillEntry,
    /// The skill's `name`.
    pub name: String,
    /// The skill's `description`.
    pub description: String,
    /// Size in bytes of its `SKILL.md`.
    pub skill_file_size: u64,
}

/// One served file.
#[derive(Debug, Clone)]
pub struct ServedFile {
    pub uri: String,
    pub mime_type: String,
    pub bytes: Arc<[u8]>,
    /// `sha256:{hex}` of `bytes`.
    pub digest: String,
}

/// One direct child of a served directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryChild {
    pub uri: String,
    /// The last path segment.
    pub name: String,
    pub mime_type: String,
    /// `None` for a directory.
    pub size: Option<u64>,
}

/// Every skill, file and directory a gateway serves.
#[derive(Debug, Default)]
pub struct SkillCatalog {
    /// Ordered by `SKILL.md` URI.
    skills: Vec<Arc<Skill>>,
    by_uri: HashMap<String, Arc<Skill>>,
    files: HashMap<String, ServedFile>,
    directories: BTreeMap<String, Vec<DirectoryChild>>,
    directory_read: bool,
    list_as_resources: bool,
}

impl SkillCatalog {
    /// Read every source of `config`. `None` when no source is configured.
    /// A relative source path resolves against `config_dir`.
    pub fn load(config: &SkillsConfig, config_dir: Option<&Path>) -> Result<Option<Self>> {
        if !config.is_enabled() {
            return Ok(None);
        }
        let mut catalog = SkillCatalog {
            directory_read: config.directory_read,
            list_as_resources: config.list_as_resources,
            ..SkillCatalog::default()
        };
        let mut directory_uris: BTreeSet<String> = BTreeSet::new();
        for (index, source) in config.sources.iter().enumerate() {
            let path = resolve(&source.path, config_dir);
            catalog
                .add_source(&path, source.prefix.as_deref(), &mut directory_uris)
                .with_context(|| format!("mcp.skills.sources[{index}] ({})", path.display()))?;
        }
        catalog.skills.sort_by(|a, b| a.entry.uri.cmp(&b.entry.uri));
        catalog.build_directories(&directory_uris);
        Ok(Some(catalog))
    }

    /// Every skill, ordered by `SKILL.md` URI.
    pub fn skills(&self) -> &[Arc<Skill>] {
        &self.skills
    }

    /// The skill whose `SKILL.md` is at `uri`.
    pub fn skill(&self, uri: &str) -> Option<&Arc<Skill>> {
        self.by_uri.get(uri)
    }

    /// The served file at `uri`.
    pub fn file(&self, uri: &str) -> Option<&ServedFile> {
        self.files.get(uri)
    }

    /// The direct children of the served directory at `uri`.
    pub fn directory(&self, uri: &str) -> Option<&[DirectoryChild]> {
        self.directories.get(uri).map(Vec::as_slice)
    }

    /// Whether `resources/directory/read` is served.
    pub fn directory_read(&self) -> bool {
        self.directory_read
    }

    /// Whether each `SKILL.md` is listed in `resources/list`.
    pub fn list_as_resources(&self) -> bool {
        self.list_as_resources
    }

    fn add_source(
        &mut self,
        root: &Path,
        prefix: Option<&str>,
        directory_uris: &mut BTreeSet<String>,
    ) -> Result<()> {
        let metadata =
            std::fs::metadata(root).with_context(|| format!("cannot read {}", root.display()))?;
        if !metadata.is_dir() {
            bail!("{} is not a folder", root.display());
        }
        let mut files: Vec<(Vec<String>, Vec<u8>)> = Vec::new();
        collect_files(root, &mut Vec::new(), &mut Vec::new(), &mut files)?;
        if files
            .iter()
            .any(|(path, _)| path.len() == 1 && path[0] == SKILL_FILE)
        {
            bail!(
                "{} holds a {SKILL_FILE} at its root; a source holds skills in its subfolders, \
                 each folder named as its skill",
                root.display()
            );
        }
        let prefix: Vec<String> = prefix
            .map(|p| p.split('/').map(str::to_owned).collect())
            .unwrap_or_default();
        let uri_of = |rel: &[String]| -> String {
            let mut segments: Vec<String> = prefix.iter().map(|s| encode_segment(s)).collect();
            segments.extend(rel.iter().map(|s| encode_segment(s)));
            format!("{SKILL_SCHEME}://{}", segments.join("/"))
        };

        let skill_dirs: Vec<Vec<String>> = files
            .iter()
            .filter(|(path, _)| path.last().map(String::as_str) == Some(SKILL_FILE))
            .map(|(path, _)| path[..path.len() - 1].to_vec())
            .collect();
        if skill_dirs.is_empty() {
            tracing::warn!(source = %root.display(), "skill source holds no {SKILL_FILE}");
        }

        for dir in &skill_dirs {
            let in_skill: Vec<&(Vec<String>, Vec<u8>)> = files
                .iter()
                .filter(|(path, _)| path.starts_with(dir))
                .collect();
            let skill_md = in_skill
                .iter()
                .find(|(path, _)| path.len() == dir.len() + 1 && path[dir.len()] == SKILL_FILE)
                .map(|(_, bytes)| bytes)
                .expect("a skill folder holds its SKILL.md");
            let folder = dir.join("/");
            let frontmatter =
                parse_frontmatter(skill_md).with_context(|| format!("{folder}/{SKILL_FILE}"))?;
            let name = frontmatter["name"].as_str().unwrap_or_default().to_owned();
            let description = frontmatter["description"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if dir.last() != Some(&name) {
                bail!(
                    "{folder}/{SKILL_FILE}: its name `{name}` is not its folder's name; \
                     a skill's folder is named as the skill"
                );
            }
            if in_skill.len() > MAX_RESOURCES_PER_SKILL {
                bail!(
                    "skill `{folder}` holds {} files; a skill holds at most \
                     {MAX_RESOURCES_PER_SKILL}",
                    in_skill.len()
                );
            }
            let total: u64 = in_skill.iter().map(|(_, b)| b.len() as u64).sum();
            if total > MAX_BYTES_PER_SKILL {
                bail!(
                    "skill `{folder}` holds {total} bytes; a skill holds at most \
                     {MAX_BYTES_PER_SKILL}"
                );
            }
            let mut listed: Vec<SkillFile> = in_skill
                .iter()
                .map(|(path, bytes)| SkillFile {
                    uri: uri_of(path),
                    digest: format_digest(&Sha256::digest(bytes)),
                    size: bytes.len() as u64,
                })
                .collect();
            listed.sort_by(|a, b| a.uri.cmp(&b.uri));
            let mut skill_path = dir.clone();
            skill_path.push(SKILL_FILE.to_owned());
            let uri = uri_of(&skill_path);
            if self.by_uri.contains_key(&uri) {
                bail!("two sources serve the skill {uri}");
            }
            let skill = Arc::new(Skill {
                entry: SkillEntry {
                    uri: uri.clone(),
                    frontmatter,
                    resources: SkillResources::Listed(listed),
                },
                name,
                description,
                skill_file_size: skill_md.len() as u64,
            });
            self.by_uri.insert(uri, skill.clone());
            self.skills.push(skill);
        }

        // A file is served when it belongs to a skill; the directories
        // that lead to it are directory resources.
        for (path, bytes) in &files {
            if !skill_dirs.iter().any(|dir| path.starts_with(dir)) {
                continue;
            }
            let uri = uri_of(path);
            if self.files.contains_key(&uri) {
                bail!("two sources serve the file {uri}");
            }
            let mime_type = mime_type_of(path.last().map(String::as_str).unwrap_or(""), bytes);
            self.files.insert(
                uri.clone(),
                ServedFile {
                    uri,
                    mime_type,
                    digest: format_digest(&Sha256::digest(bytes)),
                    bytes: Arc::from(bytes.as_slice()),
                },
            );
            let mut full: Vec<String> = prefix.clone();
            full.extend(path[..path.len() - 1].iter().cloned());
            for depth in 1..=full.len() {
                directory_uris.insert(format!(
                    "{SKILL_SCHEME}://{}",
                    full[..depth]
                        .iter()
                        .map(|s| encode_segment(s))
                        .collect::<Vec<_>>()
                        .join("/")
                ));
            }
        }
        Ok(())
    }

    fn build_directories(&mut self, directory_uris: &BTreeSet<String>) {
        let mut directories: BTreeMap<String, Vec<DirectoryChild>> = directory_uris
            .iter()
            .map(|uri| (uri.clone(), Vec::new()))
            .collect();
        let parent_of = |uri: &str| -> Option<String> {
            let (parent, _) = uri.rsplit_once('/')?;
            (parent.len() > SKILL_SCHEME.len() + 2).then(|| parent.to_owned())
        };
        let last_segment = |uri: &str| uri.rsplit('/').next().unwrap_or(uri).to_owned();
        for uri in directory_uris {
            if let Some(parent) = parent_of(uri)
                && let Some(children) = directories.get_mut(&parent)
            {
                children.push(DirectoryChild {
                    uri: uri.clone(),
                    name: last_segment(uri),
                    mime_type: DIRECTORY_MIME_TYPE.to_owned(),
                    size: None,
                });
            }
        }
        for file in self.files.values() {
            if let Some(parent) = parent_of(&file.uri)
                && let Some(children) = directories.get_mut(&parent)
            {
                children.push(DirectoryChild {
                    uri: file.uri.clone(),
                    name: last_segment(&file.uri),
                    mime_type: file.mime_type.clone(),
                    size: Some(file.bytes.len() as u64),
                });
            }
        }
        for children in directories.values_mut() {
            children.sort_by(|a, b| a.uri.cmp(&b.uri));
        }
        self.directories = directories;
    }
}

fn resolve(path: &str, config_dir: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(path);
    match config_dir {
        Some(dir) if path.is_relative() => dir.join(path),
        _ => path,
    }
}

/// Every regular file under `dir`, as its path segments below the source
/// root. Names starting with `.` are skipped. A symbolic link is followed,
/// as a Kubernetes ConfigMap mount needs; a broken link, or a folder link
/// back into a folder being walked, is refused. `walking` holds the
/// canonical paths of the folders from the root down to `dir`.
fn collect_files(
    dir: &Path,
    rel: &mut Vec<String>,
    walking: &mut Vec<PathBuf>,
    out: &mut Vec<(Vec<String>, Vec<u8>)>,
) -> Result<()> {
    let canonical =
        std::fs::canonicalize(dir).with_context(|| format!("cannot read {}", dir.display()))?;
    if walking.contains(&canonical) {
        bail!(
            "{} links back to a folder it is in; a skill source may not loop",
            dir.display()
        );
    }
    walking.push(canonical);
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot list {}", dir.display()))?
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("cannot list {}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            bail!("{} has a name that is not UTF-8", entry.path().display());
        };
        if name.starts_with('.') {
            continue;
        }
        let file_type = std::fs::metadata(entry.path())
            .with_context(|| {
                format!(
                    "cannot read {} (a broken symbolic link?)",
                    entry.path().display()
                )
            })?
            .file_type();
        rel.push(name);
        if file_type.is_dir() {
            collect_files(&entry.path(), rel, walking, out)?;
        } else if file_type.is_file() {
            let bytes = std::fs::read(entry.path())
                .with_context(|| format!("cannot read {}", entry.path().display()))?;
            out.push((rel.clone(), bytes));
        }
        rel.pop();
    }
    walking.pop();
    Ok(())
}

/// The YAML frontmatter of a `SKILL.md` as JSON, held to the Agent Skills
/// rules the extension relies on: a valid `name` and a `description`.
pub(crate) fn parse_frontmatter(bytes: &[u8]) -> Result<Map<String, Value>> {
    let text = std::str::from_utf8(bytes).context("is not UTF-8")?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.split_inclusive('\n');
    let first = lines.next().unwrap_or("");
    if first.trim_end_matches(['\r', '\n']) != "---" {
        bail!("does not begin with YAML frontmatter (a `---` line)");
    }
    let mut yaml = String::new();
    let mut closed = false;
    for line in lines {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            closed = true;
            break;
        }
        yaml.push_str(line);
    }
    if !closed {
        bail!("its frontmatter has no closing `---` line");
    }
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&yaml).context("its frontmatter is not valid YAML")?;
    let Value::Object(frontmatter) =
        serde_json::to_value(parsed).context("its frontmatter cannot be rendered as JSON")?
    else {
        bail!("its frontmatter is not a YAML mapping");
    };
    match frontmatter.get("name").and_then(Value::as_str) {
        Some(name) if is_valid_skill_name(name) => {}
        Some(name) => {
            bail!("its name `{name}` is not 1 to 64 lowercase letters, digits and single hyphens")
        }
        None => bail!("its frontmatter has no string `name`"),
    }
    match frontmatter.get("description").and_then(Value::as_str) {
        Some(d) if !d.trim().is_empty() && d.chars().count() <= MAX_DESCRIPTION_CHARS => {}
        Some(_) => {
            bail!("its description is empty or longer than {MAX_DESCRIPTION_CHARS} characters")
        }
        None => bail!("its frontmatter has no string `description`"),
    }
    Ok(frontmatter)
}

/// Percent-encode every byte of `segment` that is not URI-unreserved.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn mime_type_of(name: &str, bytes: &[u8]) -> String {
    if name == SKILL_FILE {
        return SKILL_MIME_TYPE.to_owned();
    }
    let extension = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let known = match extension.as_str() {
        "md" | "markdown" => "text/markdown",
        "txt" => "text/plain",
        "json" => "application/json",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "xml" => "application/xml",
        "js" | "mjs" => "text/javascript",
        "ts" => "text/x-typescript",
        "py" => "text/x-python",
        "sh" | "bash" | "zsh" => "text/x-shellscript",
        "rb" => "text/x-ruby",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        _ if std::str::from_utf8(bytes).is_ok() => "text/plain",
        _ => "application/octet-stream",
    };
    known.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::skills::SkillSourceConfig;

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn skill_md(name: &str, description: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: {description}\nlicense: MIT\nmetadata:\n  version: \"1.0\"\n---\n\n# {name}\n"
        )
    }

    fn config(sources: Vec<(&Path, Option<&str>)>) -> SkillsConfig {
        SkillsConfig {
            sources: sources
                .into_iter()
                .map(|(p, prefix)| SkillSourceConfig {
                    path: p.display().to_string(),
                    prefix: prefix.map(str::to_owned),
                })
                .collect(),
            ..SkillsConfig::default()
        }
    }

    fn sha(body: &str) -> String {
        format_digest(&Sha256::digest(body.as_bytes()))
    }

    #[test]
    fn no_source_serves_nothing() {
        assert!(
            SkillCatalog::load(&SkillsConfig::default(), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_source_serves_each_skill_with_every_file_and_digest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let screen = skill_md("screen", "Read the screen");
        write(root, "screen/SKILL.md", &screen);
        write(root, "screen/references/ocr.md", "ocr notes");
        write(root, "screen/.DS_Store", "skipped");
        write(root, "README.md", "not part of any skill");
        let mouse = skill_md("mouse", "Click safely");
        write(root, "mouse/SKILL.md", &mouse);

        let catalog = SkillCatalog::load(&config(vec![(root, Some("macos"))]), None)
            .unwrap()
            .unwrap();
        let uris: Vec<&str> = catalog
            .skills()
            .iter()
            .map(|s| s.entry.uri.as_str())
            .collect();
        assert_eq!(
            uris,
            [
                "skill://macos/mouse/SKILL.md",
                "skill://macos/screen/SKILL.md"
            ]
        );
        let entry = &catalog
            .skill("skill://macos/screen/SKILL.md")
            .unwrap()
            .entry;
        assert_eq!(entry.frontmatter["name"], "screen");
        assert_eq!(entry.frontmatter["license"], "MIT");
        assert_eq!(entry.frontmatter["metadata"]["version"], "1.0");
        assert_eq!(
            entry.resources,
            SkillResources::Listed(vec![
                SkillFile {
                    uri: "skill://macos/screen/SKILL.md".to_owned(),
                    digest: sha(&screen),
                    size: screen.len() as u64,
                },
                SkillFile {
                    uri: "skill://macos/screen/references/ocr.md".to_owned(),
                    digest: sha("ocr notes"),
                    size: 9,
                },
            ])
        );
        let file = catalog
            .file("skill://macos/screen/references/ocr.md")
            .unwrap();
        assert_eq!(&*file.bytes, b"ocr notes");
        assert_eq!(file.mime_type, "text/markdown");
        assert_eq!(
            catalog
                .file("skill://macos/screen/SKILL.md")
                .unwrap()
                .mime_type,
            "text/markdown"
        );
        assert!(catalog.file("skill://macos/screen/.DS_Store").is_none());
        assert!(catalog.file("skill://macos/README.md").is_none());
    }

    #[test]
    fn every_directory_level_lists_its_direct_children() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "screen/SKILL.md", &skill_md("screen", "d"));
        write(root, "screen/references/ocr.md", "x");
        write(root, "mouse/SKILL.md", &skill_md("mouse", "d"));
        let catalog = SkillCatalog::load(&config(vec![(root, Some("acme/mac"))]), None)
            .unwrap()
            .unwrap();
        let names = |uri: &str| -> Vec<(String, String)> {
            catalog
                .directory(uri)
                .unwrap_or_else(|| panic!("{uri} is a directory"))
                .iter()
                .map(|c| (c.name.clone(), c.mime_type.clone()))
                .collect()
        };
        let dir_mime = DIRECTORY_MIME_TYPE.to_owned();
        assert_eq!(
            names("skill://acme"),
            [("mac".to_owned(), dir_mime.clone())]
        );
        assert_eq!(
            names("skill://acme/mac"),
            [
                ("mouse".to_owned(), dir_mime.clone()),
                ("screen".to_owned(), dir_mime.clone())
            ]
        );
        assert_eq!(
            names("skill://acme/mac/screen"),
            [
                ("SKILL.md".to_owned(), "text/markdown".to_owned()),
                ("references".to_owned(), dir_mime.clone())
            ]
        );
        assert_eq!(
            names("skill://acme/mac/screen/references"),
            [("ocr.md".to_owned(), "text/markdown".to_owned())]
        );
        assert!(
            catalog
                .directory("skill://acme/mac/screen/SKILL.md")
                .is_none()
        );
        assert!(catalog.directory("skill://acme/mac/nothing").is_none());
    }

    #[test]
    fn a_nested_skill_is_its_own_skill_and_a_file_of_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "outer/SKILL.md", &skill_md("outer", "d"));
        write(root, "outer/inner/SKILL.md", &skill_md("inner", "d"));
        let catalog = SkillCatalog::load(&config(vec![(root, None)]), None)
            .unwrap()
            .unwrap();
        let SkillResources::Listed(outer) = &catalog
            .skill("skill://outer/SKILL.md")
            .unwrap()
            .entry
            .resources
        else {
            panic!("listed")
        };
        assert!(
            outer
                .iter()
                .any(|f| f.uri == "skill://outer/inner/SKILL.md")
        );
        assert!(catalog.skill("skill://outer/inner/SKILL.md").is_some());
    }

    #[test]
    fn a_relative_source_resolves_against_the_config_folder() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "skills/screen/SKILL.md",
            &skill_md("screen", "d"),
        );
        let config = SkillsConfig {
            sources: vec![SkillSourceConfig {
                path: "skills".to_owned(),
                prefix: None,
            }],
            ..SkillsConfig::default()
        };
        let catalog = SkillCatalog::load(&config, Some(dir.path()))
            .unwrap()
            .unwrap();
        assert!(catalog.skill("skill://screen/SKILL.md").is_some());
    }

    #[test]
    fn a_file_name_outside_the_unreserved_set_is_percent_encoded() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "screen/SKILL.md", &skill_md("screen", "d"));
        write(dir.path(), "screen/my notes.md", "x");
        let catalog = SkillCatalog::load(&config(vec![(dir.path(), None)]), None)
            .unwrap()
            .unwrap();
        assert!(catalog.file("skill://screen/my%20notes.md").is_some());
    }

    #[test]
    fn a_bad_source_is_refused_with_the_reason() {
        let cases: Vec<(&str, Box<dyn Fn(&Path)>)> = vec![
            (
                "its name `other` is not its folder's name",
                Box::new(|r: &Path| write(r, "screen/SKILL.md", &skill_md("other", "d"))),
            ),
            (
                "no string `description`",
                Box::new(|r: &Path| write(r, "screen/SKILL.md", "---\nname: screen\n---\n")),
            ),
            (
                "is not 1 to 64 lowercase",
                Box::new(|r: &Path| write(r, "Screen/SKILL.md", &skill_md("Screen", "d"))),
            ),
            (
                "does not begin with YAML frontmatter",
                Box::new(|r: &Path| write(r, "screen/SKILL.md", "# no frontmatter\n")),
            ),
            (
                "no closing `---`",
                Box::new(|r: &Path| write(r, "screen/SKILL.md", "---\nname: screen\n")),
            ),
            (
                "holds a SKILL.md at its root",
                Box::new(|r: &Path| write(r, "SKILL.md", &skill_md("x", "d"))),
            ),
        ];
        for (why, setup) in cases {
            let dir = tempfile::tempdir().unwrap();
            setup(dir.path());
            let error = format!(
                "{:#}",
                SkillCatalog::load(&config(vec![(dir.path(), None)]), None).unwrap_err()
            );
            assert!(error.contains(why), "{why}: {error}");
        }
    }

    #[test]
    fn two_sources_may_not_serve_the_same_skill() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(a.path(), "screen/SKILL.md", &skill_md("screen", "d"));
        write(b.path(), "screen/SKILL.md", &skill_md("screen", "d"));
        let error = format!(
            "{:#}",
            SkillCatalog::load(&config(vec![(a.path(), None), (b.path(), None)]), None)
                .unwrap_err()
        );
        assert!(
            error.contains("two sources serve the skill skill://screen/SKILL.md"),
            "{error}"
        );
    }

    #[test]
    fn a_skill_above_the_file_limit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "big/SKILL.md", &skill_md("big", "d"));
        for i in 0..MAX_RESOURCES_PER_SKILL {
            write(dir.path(), &format!("big/f{i}.txt"), "x");
        }
        let error = format!(
            "{:#}",
            SkillCatalog::load(&config(vec![(dir.path(), None)]), None).unwrap_err()
        );
        assert!(error.contains("holds 513 files"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_configmap_style_mount_of_links_is_served() {
        // A ConfigMap volume: visible names link into `..data`, which links
        // to a dated folder the kubelet swaps on update.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "..2026_11_09/screen/SKILL.md",
            &skill_md("screen", "d"),
        );
        std::os::unix::fs::symlink("..2026_11_09", root.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/screen", root.join("screen")).unwrap();
        let catalog = SkillCatalog::load(&config(vec![(root, None)]), None)
            .unwrap()
            .unwrap();
        let uris: Vec<&str> = catalog
            .skills()
            .iter()
            .map(|s| s.entry.uri.as_str())
            .collect();
        assert_eq!(uris, ["skill://screen/SKILL.md"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_broken_link_or_a_link_loop_is_refused() {
        let broken = tempfile::tempdir().unwrap();
        write(broken.path(), "screen/SKILL.md", &skill_md("screen", "d"));
        std::os::unix::fs::symlink("missing.txt", broken.path().join("screen/link.txt")).unwrap();
        let error = format!(
            "{:#}",
            SkillCatalog::load(&config(vec![(broken.path(), None)]), None).unwrap_err()
        );
        assert!(error.contains("a broken symbolic link?"), "{error}");

        let looped = tempfile::tempdir().unwrap();
        write(looped.path(), "screen/SKILL.md", &skill_md("screen", "d"));
        std::os::unix::fs::symlink("..", looped.path().join("screen/up")).unwrap();
        let error = format!(
            "{:#}",
            SkillCatalog::load(&config(vec![(looped.path(), None)]), None).unwrap_err()
        );
        assert!(error.contains("links back to a folder it is in"), "{error}");
    }

    #[test]
    fn a_binary_file_gets_a_binary_mime_type() {
        assert_eq!(mime_type_of("logo.png", &[0x89, b'P']), "image/png");
        assert_eq!(
            mime_type_of("blob", &[0xff, 0xfe, 0x00]),
            "application/octet-stream"
        );
        assert_eq!(mime_type_of("notes", b"plain"), "text/plain");
    }
}
