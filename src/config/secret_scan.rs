//! Secret-reference scanner over a loaded `AppConfig`.
//!
//! Walks the config as a `serde_json::Value` and surfaces every
//! `${env.VAR}` and `<scheme>://...` reference along with the
//! config path that contained it. Two consumers:
//!
//! 1. The boot-time audit emit (`mcpg.config.secrets_resolved`)
//!    — auditors get an explicit "what secrets does this gateway
//!    consume" record alongside `mcpg.config.loaded`.
//! 2. The `mcpg config secrets` subcommand — operator-facing pretty
//!    table for "which secrets will rotate if I rotate
//!    `GITHUB_TOKEN`" investigations.

use serde::Serialize;

/// One reference discovered while scanning the config tree.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretRef {
    /// Whether this ref is an env-var lookup (`${env.VAR}`) or a
    /// secret-provider URI (`vault://...`, `aws-sm://...`, etc).
    pub kind: SecretRefKind,
    /// For [`SecretRefKind::EnvVar`]: the variable name. For
    /// [`SecretRefKind::SecretUri`]: the full URI string.
    pub name: String,
    /// Dotted/bracketed path to the field that contained the ref
    /// (e.g. `bindings[0].headers.Authorization`,
    /// `oauth.providers.analytics.client_secret`).
    pub field_path: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SecretRefKind {
    EnvVar,
    SecretUri,
}

/// Schemes that look URI-shaped but are NOT secret-provider refs.
/// Anything outside this set, when occupying the entire string
/// value, is treated as a candidate secret URI.
const NON_SECRET_SCHEMES: &[&str] = &[
    "http",
    "https",
    "ws",
    "wss",
    "file",
    "ftp",
    "ftps",
    "ldap",
    "ldaps",
    "smtp",
    "smtps",
    "data",
    "mailto",
    "redis",
    "rediss",
    "nats",
    "tls",
    "kafka",
    "postgres",
    "postgresql",
    "mongodb",
    "mongodb+srv",
    "mysql",
    "grpc",
    "grpcs",
    "sqlite",
];

/// Walk `config` (serialised as JSON) and surface every secret ref
/// it contains. Output is sorted + deduplicated, so two structurally
/// equivalent configs produce the same list.
pub fn scan_app_config(config: &crate::config::AppConfig) -> Vec<SecretRef> {
    let value = serde_json::to_value(config).expect("AppConfig serialises");
    let mut acc = Vec::new();
    scan_value(&value, "", &mut acc);
    acc.sort();
    acc.dedup();
    acc
}

/// Recursive walker — public so the secrets binary can scan a raw
/// `Value` (e.g. multi-file YAML merged outside the gateway boot
/// path). Keeps the binary independent of `AppConfig`'s typed shape.
pub fn scan_value(value: &serde_json::Value, path: &str, acc: &mut Vec<SecretRef>) {
    match value {
        serde_json::Value::String(s) => scan_string(s, path, acc),
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let child_path = format!("{path}[{i}]");
                scan_value(v, &child_path, acc);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                scan_value(v, &child_path, acc);
            }
        }
        _ => {}
    }
}

/// String-leaf scanner. Picks up:
/// - Every `${env.VAR}` substring in the value (variables can
///   appear inline inside larger templates: `"Bearer ${env.X}"`).
/// - When the entire string is a `<scheme>://...` URI with a scheme
///   that isn't a well-known transport / DB driver, the URI is
///   surfaced as a `SecretUri` candidate.
fn scan_string(s: &str, path: &str, acc: &mut Vec<SecretRef>) {
    // 1. Env refs — `${env.X}`; multiple per string allowed.
    for prefix in ["${env."] {
        let mut search_from = 0usize;
        while let Some(rel) = s[search_from..].find(prefix) {
            let abs = search_from + rel;
            let after_prefix = abs + prefix.len();
            let name_end = s[after_prefix..]
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .map(|p| after_prefix + p)
                .unwrap_or(s.len());
            let name = &s[after_prefix..name_end];
            if !name.is_empty() {
                acc.push(SecretRef {
                    kind: SecretRefKind::EnvVar,
                    name: name.to_owned(),
                    field_path: path.to_owned(),
                });
            }
            search_from = name_end;
        }
    }

    // 2. `${cred://issuer/target}` credential tokens — the standardized
    // credential-reference form. Use the shared helper so the audit
    // recognizes exactly what the backends resolve.
    for uri in mcpg_plugin_protocol::credential::cred_tokens(s) {
        acc.push(SecretRef {
            kind: SecretRefKind::SecretUri,
            name: uri,
            field_path: path.to_owned(),
        });
    }

    // 3. Whole-string secret URI (e.g. `vault://…`) — scheme must look
    // like an identifier and NOT match a known non-secret transport. Skip
    // when an env ref or a `${cred://}` token is in play (already
    // captured above) to avoid double-counting.
    if let Some(idx) = s.find("://")
        && idx > 0
    {
        let scheme = &s[..idx];
        let is_id = scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+');
        let is_known_transport = NON_SECRET_SCHEMES.contains(&scheme);
        let has_env = s.contains("${env.");
        let has_cred_token = s.contains("${cred://");
        if is_id && !is_known_transport && !has_env && !has_cred_token {
            acc.push(SecretRef {
                kind: SecretRefKind::SecretUri,
                name: s.to_owned(),
                field_path: path.to_owned(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scan(value: serde_json::Value) -> Vec<SecretRef> {
        let mut acc = Vec::new();
        scan_value(&value, "", &mut acc);
        acc.sort();
        acc
    }

    #[test]
    fn env_ref_in_a_simple_string() {
        let refs = scan(json!({"key": "Bearer ${env.GH_TOKEN}"}));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, SecretRefKind::EnvVar);
        assert_eq!(refs[0].name, "GH_TOKEN");
        assert_eq!(refs[0].field_path, "key");
    }

    #[test]
    fn multiple_env_refs_in_one_string() {
        let refs = scan(json!({"url": "https://${env.HOST}:${env.PORT}/x"}));
        let names: Vec<_> = refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["HOST", "PORT"]);
    }

    #[test]
    fn env_ref_inside_nested_array_path() {
        let refs = scan(json!({
            "bindings": [
                {"headers": {"Authorization": "${env.TOKEN}"}}
            ]
        }));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "TOKEN");
        assert_eq!(refs[0].field_path, "bindings[0].headers.Authorization");
    }

    #[test]
    fn vault_uri_classified_as_secret_uri() {
        let refs = scan(json!({"db_password": "vault://secret/db#password"}));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].kind, SecretRefKind::SecretUri);
        assert_eq!(refs[0].name, "vault://secret/db#password");
        assert_eq!(refs[0].field_path, "db_password");
    }

    #[test]
    fn http_uri_is_not_a_secret_ref() {
        let refs = scan(json!({"url": "https://api.example.com/v1"}));
        assert!(refs.is_empty());
    }

    #[test]
    fn redis_url_is_not_a_secret_ref() {
        let refs = scan(json!({"url": "redis://localhost:6379"}));
        assert!(refs.is_empty());
    }

    #[test]
    fn env_in_uri_template_dedupes_secret_uri() {
        // The string contains both an env ref AND a URI shape; we
        // surface only the env ref to avoid double-counting.
        let refs = scan(json!({"url": "vault://${env.VAULT_PATH}"}));
        let kinds: Vec<_> = refs.iter().map(|r| r.kind).collect();
        assert_eq!(kinds, vec![SecretRefKind::EnvVar]);
    }

    #[test]
    fn output_is_sorted_and_deduplicated() {
        let refs = scan(json!({
            "a": "${env.Z}",
            "b": "${env.A}",
            "c": "${env.A}", // duplicate name + different path
        }));
        // Sorted by (kind, name, path):
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].name, "A");
        assert_eq!(refs[1].name, "A");
        assert_eq!(refs[2].name, "Z");
    }

    #[test]
    fn scan_app_config_default_returns_empty() {
        let cfg = crate::config::AppConfig::default();
        let refs = scan_app_config(&cfg);
        assert!(
            refs.is_empty(),
            "default config should have no secret refs: {refs:?}"
        );
    }
}
