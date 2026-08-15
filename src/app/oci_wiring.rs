use super::*;

/// Resolve a plugin's OCI reference to a local `.zip` on disk,
/// pulling from the registry (or one of its mirrors) when the
/// local cache doesn't already have a matching manifest digest.
///
/// The returned path points inside the gateway's OCI pull cache
/// (`plugin_registry.cache_dir` or `$XDG_CACHE_HOME/mcpg/plugins/oci`
/// by default) and is safe to hand to [`load_packaged_plugin`].
///
/// Authentication follows `plugin_registry.auth`:
/// `username`+`password` (with `env:VAR` and `$VAR` interpolation)
/// takes precedence, otherwise fall back to anonymous. Docker
/// config.json helper integration is out-of-scope here — it would
/// require oci-client's optional feature; noted for follow-up.
///
/// The reference may be: `registry/repo:tag`, `repo:tag` (uses
/// `plugin_registry.default_registry`), or
/// `registry/repo@sha256:...` (digest-pinned, content-addressed,
/// skips network on cache hit).
/// Under `plugin_registry.require_integrity_anchor`, refuse an `oci:`
/// entry that lacks an anchor the gateway can enforce independently of
/// the transport: a digest-pinned reference (`…@sha256:<hex>`), a
/// `signature.sha256` / `integrity.sha256` layer pin, or
/// `signature.trusted_keys`. A bare-tag pull over a mirror / insecure
/// hop is otherwise trusted on the registry's word alone.
pub(crate) fn enforce_oci_integrity_anchor(
    entry: &crate::config::PluginEntryConfig,
    oci_ref: &str,
    registry_cfg: &crate::config::PluginRegistryConfig,
) -> Result<()> {
    if !registry_cfg.require_integrity_anchor {
        return Ok(());
    }
    let has_digest_pin = oci_ref.contains("@sha256:");
    let has_layer_pin = entry
        .signature
        .as_ref()
        .and_then(|s| s.sha256.as_deref())
        .is_some();
    let has_trusted_keys = entry
        .signature
        .as_ref()
        .is_some_and(|s| !s.trusted_keys.is_empty());
    if has_digest_pin || has_layer_pin || has_trusted_keys {
        return Ok(());
    }
    anyhow::bail!(
        "plugin '{}': plugin_registry.require_integrity_anchor is set but the oci source \
         '{oci_ref}' has no integrity anchor — pin a digest (…@sha256:<hex>), set \
         signature.sha256, or configure signature.trusted_keys",
        entry.id,
    );
}

pub(crate) fn resolve_oci_source(
    reference: &str,
    plugin_id: &str,
    registry_cfg: &crate::config::PluginRegistryConfig,
) -> Result<std::path::PathBuf> {
    // ── Platform / protocol resolution (Path B) ────────────────────────
    // A config `oci:` ref may be PLATFORM-AGNOSTIC. Expand it into the
    // concrete per-platform artifact tag(s) the CD publish side emits
    // (`<repo>:<tag>-<os>[-musl]-<arch>` / `-wasi-wasm`, plus the floating
    // `protocol-<major>-<platform>`):
    //   • no tag                 → `:protocol-<major>-<platform>` — track the
    //                              floating tag for the protocol this gateway
    //                              speaks (native preferred, wasm fallback)
    //   • tag without a platform  → `<tag>-<platform>` (native + wasm)
    //   • tag WITH a platform / @digest → pulled verbatim (explicit pin)
    // The gateway knows its own os/arch/libc at COMPILE time (which an OCI
    // image index can't express — no libc descriptor), so musl vs gnu
    // resolves cleanly. The native→wasm ordering rides the mirror/primary
    // retry loop below, so a bare ref "just works" for native AND wasm
    // plugins.
    let platform_refs = platform_candidate_refs(reference);
    let normalised_candidates: Vec<String> = platform_refs
        .iter()
        .map(|r| normalise_oci_reference(r, &registry_cfg.default_registry))
        .collect();
    // The first (native-preferred) candidate names the cache file and drives
    // the digest fast-path + auth host; all candidates share one registry +
    // repository, differing only in tag.
    let normalised = normalised_candidates[0].clone();
    if normalised.as_str() != reference {
        info!(
            plugin_id = %plugin_id,
            configured = %reference,
            resolved = %normalised,
            "resolved OCI plugin reference (platform / registry)"
        );
    }
    let cache_base = resolve_oci_cache_dir(registry_cfg);
    std::fs::create_dir_all(&cache_base).map_err(|e| {
        anyhow::anyhow!(
            "plugin '{plugin_id}': cannot create OCI cache dir {}: {e}",
            cache_base.display()
        )
    })?;

    // Cache filename is the sanitised reference. Two references
    // with different digests get different files; digest-pinned
    // refs are stable forever; tag-based refs are re-pulled on
    // every boot (registry may have updated the tag — we rely on
    // the registry's content-addressable guarantee to avoid
    // re-downloading blobs that the local pulled file already
    // matches).
    let cache_name = sanitize_for_path(&normalised).replace('/', "_") + ".zip";
    let cache_path = cache_base.join(&cache_name);

    // Cache-hit fast path. The cached file holds the LAYER (zip) bytes, so
    // it can only be validated against a digest in that SAME domain. The
    // only such digest is the one a previous successful pull recorded in the
    // sidecar (from the exact persisted bytes). Two other digests are in
    // DIFFERENT domains and deliberately NOT used here: an `@sha256:`
    // reference pins the MANIFEST (re-asserted at pull time instead), and
    // `signature.sha256`/`integrity.sha256` pin the UNPACKED artifact
    // (`.so`/`.wasm`) — both unrelated to the zip bytes. The operator pin +
    // signature + revocation gate is enforced downstream by
    // `verify_native_artifact` on every boot regardless of a cache hit, so
    // this fast path is purely a re-pull optimization: a sidecar mismatch
    // (or missing sidecar) just forces a clean re-pull, never a bad load.
    let sidecar_path = oci_cache_sidecar_path(&cache_path);
    let cache_anchor: Option<String> = read_oci_cache_sidecar(&sidecar_path);
    if let Some(expected) = cache_anchor.as_deref()
        && cache_path.exists()
    {
        match verify_cached_digest(&cache_path, expected) {
            Ok(()) => {
                info!(
                    plugin_id = %plugin_id,
                    reference = %normalised,
                    cache = %cache_path.display(),
                    "OCI cache hit — layer digest verified, skipping pull"
                );
                return Ok(cache_path);
            }
            Err(err) => {
                // Don't abort — the pull path below will replace the
                // bogus cached file. But log loudly: this is either
                // a tampered cache (attack) or a crashed-mid-write
                // partial pull (bug). Either way operators need to
                // see it.
                warn!(
                    plugin_id = %plugin_id,
                    reference = %normalised,
                    cache = %cache_path.display(),
                    error = %err,
                    "OCI cache entry failed digest verification — discarding and re-pulling"
                );
                let _ = std::fs::remove_file(&cache_path);
                let _ = std::fs::remove_file(&sidecar_path);
            }
        }
    }

    let primary_host = registry_host_from_reference(&normalised);
    let auth = resolve_oci_auth(&registry_cfg.auth, &primary_host)?;
    // Try each platform candidate (native → wasm fallback) and, within each,
    // mirrors before the primary source. So every source is exhausted for the
    // PREFERRED (native) artifact before falling back to the wasm variant —
    // a native plugin succeeds on the first attempt; a wasm-only plugin costs
    // one quick 404 per native source before the wasm candidate resolves.
    let attempt_refs: Vec<(String, mcpg_plugin_host::oci::OciAuth)> = {
        let mut v: Vec<(String, mcpg_plugin_host::oci::OciAuth)> = Vec::new();
        for candidate in &normalised_candidates {
            for mirror in &registry_cfg.mirrors {
                let mirror_ref = rewrite_reference_for_mirror(candidate, &mirror.url);
                let mirror_host = registry_host_from_reference(&mirror_ref);
                let mirror_auth = mirror
                    .auth
                    .as_ref()
                    .map(|auth_cfg| resolve_oci_auth(auth_cfg, &mirror_host))
                    .transpose()?
                    .unwrap_or_else(|| auth.clone());
                v.push((mirror_ref, mirror_auth));
            }
            v.push((candidate.clone(), auth.clone()));
        }
        v
    };

    // Plugin loading runs from a sync loop in `build_from_config`,
    // which is itself awaited by `#[tokio::main]`. We must NOT build
    // a nested runtime (tokio rejects that with "Cannot start a
    // runtime from within a runtime"). Instead, use `block_in_place`
    // to mark this worker thread as blocking and run the async pull
    // on the current multi-threaded runtime.
    //
    // If we're invoked outside of a tokio context (e.g. a future
    // `mcpg plugin pull`-only CLI path), fall back to spinning up a
    // short-lived runtime ourselves.
    let client_options = mcpg_plugin_host::oci::OciClientOptions {
        insecure_registries: registry_cfg.insecure_registries.clone(),
    };
    let run_pull =
        |candidate: String,
         candidate_auth: mcpg_plugin_host::oci::OciAuth,
         cache_path: std::path::PathBuf|
         -> Result<mcpg_plugin_host::oci::PullOutcome, mcpg_plugin_host::oci::OciError> {
            let options = client_options.clone();
            // A digest-pinned candidate (`…@sha256:<hex>`) is re-asserted
            // against the resolved manifest digest inside `pull`, before the
            // layer is written to the cache.
            let pinned_manifest_digest = digest_from_reference(&candidate);
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => tokio::task::block_in_place(|| {
                    handle.block_on(mcpg_plugin_host::oci::pull(
                        &candidate,
                        &cache_path,
                        candidate_auth,
                        options,
                        pinned_manifest_digest,
                    ))
                }),
                Err(_) => {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("build standalone tokio runtime for OCI pull");
                    rt.block_on(mcpg_plugin_host::oci::pull(
                        &candidate,
                        &cache_path,
                        candidate_auth,
                        options,
                        pinned_manifest_digest,
                    ))
                }
            }
        };

    let mut last_err: Option<anyhow::Error> = None;
    for (candidate, candidate_auth) in attempt_refs {
        info!(
            plugin_id = %plugin_id,
            candidate = %candidate,
            "pulling OCI plugin artefact"
        );
        let result = run_pull(candidate.clone(), candidate_auth, cache_path.clone());
        match result {
            Ok(outcome) => {
                info!(
                    plugin_id = %plugin_id,
                    candidate = %candidate,
                    manifest_digest = %outcome.manifest_digest,
                    layer_digest = %outcome.layer_digest,
                    path = %cache_path.display(),
                    "OCI pull succeeded"
                );
                // Record the layer digest next to the cache file so a
                // later boot can validate the cache without re-pulling.
                write_oci_cache_sidecar(&sidecar_path, &outcome.layer_digest);
                return Ok(cache_path);
            }
            Err(err) => {
                warn!(
                    plugin_id = %plugin_id,
                    candidate = %candidate,
                    error = %err,
                    "OCI pull attempt failed — trying next candidate"
                );
                last_err = Some(anyhow::Error::new(err));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow::anyhow!("plugin '{plugin_id}': OCI resolution produced no candidates")
    }))
}

/// Prepend the default registry when a reference has no registry
/// prefix. Leaves explicit references (`ghcr.io/...`,
/// `registry.internal.corp/...`, `localhost:5000/...`)
/// untouched.
///
/// The OCI reference grammar is ambiguous on its own
/// (`audit:1.0` vs `localhost:5000`), so we follow Docker's
/// heuristic: a reference is "qualified" (has an explicit
/// registry) iff it contains a `/` AND the segment before the
/// first `/` is registry-shaped (has a `.`, has a `:` for port,
/// or equals `localhost`).
pub(crate) fn normalise_oci_reference(reference: &str, default_registry: &str) -> String {
    let looks_qualified = match reference.split_once('/') {
        Some((first, _rest)) => first.contains('.') || first.contains(':') || first == "localhost",
        None => false, // no `/` → nothing to treat as a registry
    };
    if looks_qualified {
        reference.to_owned()
    } else {
        format!(
            "{}/{}",
            default_registry.trim_end_matches('/'),
            reference.trim_start_matches('/')
        )
    }
}

/// Platform-suffix tokens the CD publish side appends to plugin OCI tags
/// (`tools/release/publish-plugin.sh`: `<os>[-musl]-<arch>`, plus the WASM
/// `wasi-wasm`). The pull-side resolver MUST stay byte-identical to this
/// contract — a NEW shipped platform needs a token here too.
pub(crate) const PLATFORM_SUFFIX_TOKENS: &[&str] = &[
    "linux-amd64",
    "linux-arm64",
    "linux-musl-amd64",
    "linux-musl-arm64",
    "darwin-amd64",
    "darwin-arm64",
    "windows-amd64",
    "windows-arm64",
    "wasi-wasm",
];

/// This gateway's native plugin-artifact platform token — the os/arch/libc
/// it can `dlopen`, resolved at COMPILE time. Matches the CD suffix tokens.
pub(crate) fn native_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "darwin-arm64"
        } else {
            "darwin-amd64"
        }
    } else if cfg!(target_os = "windows") {
        if cfg!(target_arch = "aarch64") {
            "windows-arm64"
        } else {
            "windows-amd64"
        }
    } else {
        // Linux (and any other unix fallback): glibc unless built for musl.
        match (cfg!(target_env = "musl"), cfg!(target_arch = "aarch64")) {
            (true, true) => "linux-musl-arm64",
            (true, false) => "linux-musl-amd64",
            (false, true) => "linux-arm64",
            (false, false) => "linux-amd64",
        }
    }
}

/// The plugin-protocol MAJOR this gateway speaks (`PROTOCOL_VERSION`'s
/// leading component) — the `protocol-<major>` floating tag a tag-less
/// `oci:` ref tracks.
pub(crate) fn protocol_major() -> &'static str {
    mcpg_plugin_protocol::PROTOCOL_VERSION
        .split('.')
        .next()
        .unwrap_or("1")
}

/// True if `tag` already ends with a known platform suffix — i.e. the
/// operator pinned a concrete artifact and we must pull it verbatim.
pub(crate) fn tag_has_platform_suffix(tag: &str) -> bool {
    PLATFORM_SUFFIX_TOKENS
        .iter()
        .any(|s| tag == *s || tag.ends_with(&format!("-{s}")))
}

/// Expand a (possibly platform-agnostic) config `oci:` reference into the
/// concrete artifact candidate(s) to pull, native-preferred. Thin wrapper
/// over [`resolve_platform_candidates`] supplying this gateway's compiled
/// platform + protocol major.
pub(crate) fn platform_candidate_refs(reference: &str) -> Vec<String> {
    resolve_platform_candidates(reference, native_platform(), protocol_major())
}

/// Pure core of [`platform_candidate_refs`] (platform + protocol injected so
/// every os/arch/libc combination is unit-testable). Resolution rules are
/// documented at the [`resolve_oci_source`] call site.
pub(crate) fn resolve_platform_candidates(
    reference: &str,
    native: &str,
    major: &str,
) -> Vec<String> {
    // A digest pin (`@sha256:…` / any `@…`) is an explicit, content-addressed,
    // inherently platform-specific reference — never rewrite it.
    if reference.contains('@') {
        return vec![reference.to_owned()];
    }
    // The tag colon lives in the LAST path segment (after the final `/`), so a
    // `host:port` registry colon is never mistaken for a tag.
    let seg_start = reference.rfind('/').map_or(0, |i| i + 1);
    let last_segment = &reference[seg_start..];
    match last_segment.find(':') {
        // No tag → track the floating protocol tag for this platform.
        None => vec![
            format!("{reference}:protocol-{major}-{native}"),
            format!("{reference}:protocol-{major}-wasi-wasm"),
        ],
        Some(rel_colon) => {
            let tag = &last_segment[rel_colon + 1..];
            if tag_has_platform_suffix(tag) {
                // Explicit platform pin — pull verbatim.
                vec![reference.to_owned()]
            } else {
                // Bare version/tag → append this platform's suffix.
                vec![
                    format!("{reference}-{native}"),
                    format!("{reference}-wasi-wasm"),
                ]
            }
        }
    }
}

/// If the reference pins an OCI digest (`foo@sha256:<64-hex>`),
/// return the hex-encoded digest. Otherwise None (tag-based refs).
pub(crate) fn digest_from_reference(reference: &str) -> Option<&str> {
    let (_, after) = reference.rsplit_once("@sha256:")?;
    // Validate it really is 64 lowercase hex chars — defends against
    // junk like `foo@sha256:notadigest` sneaking past and producing
    // misleading "verification failed" errors.
    if after.len() == 64 && after.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(after)
    } else {
        None
    }
}

/// Path of the layer-digest sidecar written alongside a cached OCI
/// plugin zip. Records the layer-bytes SHA-256 the pull persisted so a
/// later boot can validate the cache (layer-content domain) without a
/// re-pull.
pub(crate) fn oci_cache_sidecar_path(cache_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = cache_path.as_os_str().to_owned();
    name.push(".layer-sha256");
    std::path::PathBuf::from(name)
}

/// Read the bare-hex layer digest recorded in a cache sidecar, if any.
/// A missing or malformed sidecar yields `None` so the cache is treated
/// as unanchored (forcing a re-pull rather than trusting junk).
pub(crate) fn read_oci_cache_sidecar(sidecar_path: &std::path::Path) -> Option<String> {
    let raw = std::fs::read_to_string(sidecar_path).ok()?;
    let trimmed = raw.trim();
    let hex = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hex.to_owned())
    } else {
        None
    }
}

/// Persist the layer digest next to the cached zip. Best-effort: a
/// read-only cache dir degrades to re-pull-every-boot, not a boot
/// failure.
pub(crate) fn write_oci_cache_sidecar(sidecar_path: &std::path::Path, layer_digest: &str) {
    if let Err(e) = std::fs::write(sidecar_path, layer_digest) {
        warn!(
            sidecar = %sidecar_path.display(),
            error = %e,
            "could not write OCI cache digest sidecar — cache will re-pull next boot"
        );
    }
}

/// Verify that the file at `path` hashes to `expected_hex` under
/// SHA-256. Returns `Err` with the computed digest on mismatch so
/// the caller can log it for forensics.
pub(crate) fn verify_cached_digest(path: &std::path::Path, expected_hex: &str) -> Result<()> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let got = mcpg_plugin_host::verify::sha256_hex(&bytes);
    if got.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "cached digest mismatch: expected {expected_hex}, got {got}"
        ))
    }
}

/// Swap the registry prefix of a normalised reference with the
/// mirror's URL. The repository + tag / digest segments are
/// preserved.
pub(crate) fn rewrite_reference_for_mirror(reference: &str, mirror_url: &str) -> String {
    // Everything after the first `/` is the repository path.
    let mut parts = reference.splitn(2, '/');
    let _registry = parts.next().unwrap_or("");
    let repo_and_tag = parts.next().unwrap_or("");
    format!(
        "{}/{}",
        mirror_url.trim_end_matches('/'),
        repo_and_tag.trim_start_matches('/')
    )
}

/// Extract the registry host from a normalised OCI reference.
///
/// Takes the portion before the first `/`. An unqualified reference
/// (no `/`) would have been rejected upstream by
/// `normalise_oci_reference` — by the time a ref reaches this point it
/// has a registry prefix.
///
/// Strips any leading scheme (`https://`, `http://`) and a trailing
/// path-or-port suffix is kept as-is (Docker stores hosts as
/// `host[:port]`, so ports are part of the matching key).
pub(crate) fn registry_host_from_reference(reference: &str) -> String {
    let stripped = reference
        .strip_prefix("https://")
        .or_else(|| reference.strip_prefix("http://"))
        .unwrap_or(reference);
    stripped
        .split_once('/')
        .map(|(host, _)| host.to_owned())
        .unwrap_or_else(|| stripped.to_owned())
}

/// Pick the OCI pull cache dir from config, falling back to the
/// OS cache convention.
pub(crate) fn resolve_oci_cache_dir(
    registry_cfg: &crate::config::PluginRegistryConfig,
) -> std::path::PathBuf {
    if let Some(ref dir) = registry_cfg.cache_dir {
        return std::path::PathBuf::from(dir);
    }
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME")
        && !xdg.is_empty()
    {
        return std::path::PathBuf::from(xdg)
            .join("mcpg")
            .join("plugins")
            .join("oci");
    }
    // Fallback order: $HOME/.cache, /var/cache/mcpg, /tmp/mcpg.
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        return std::path::PathBuf::from(home)
            .join(".cache")
            .join("mcpg")
            .join("plugins")
            .join("oci");
    }
    std::path::PathBuf::from("/var/cache/mcpg/plugins/oci")
}

/// Materialise `PluginRegistryAuthConfig` into the
/// `mcpg-plugin-host::oci::OciAuth` the client consumes.
///
/// Precedence (matches the spec `plugins.registry.auth` model):
///
/// 1. Explicit `username` + `password` pair (with `env:VAR` / `$VAR`
///    interpolation supported on each).
/// 2. Docker `config.json` at `docker_config_path` (or
///    `~/.docker/config.json` if the path is left default), consulted
///    for `host`. Supports inline base64 `auth` fields and external
///    credential helpers per the Docker spec.
/// 3. Anonymous — public registry or cached-only read path.
///
/// `host` is derived from the OCI reference the caller is about to
/// push/pull. It's required when we fall through to the Docker config
/// (which is keyed by host); anything above #2 doesn't need it.
pub(crate) fn resolve_oci_auth(
    auth: &crate::config::PluginRegistryAuthConfig,
    host: &str,
) -> Result<mcpg_plugin_host::oci::OciAuth> {
    let user = auth.username.as_deref().map(interpolate_env).transpose()?;
    let pass = auth
        .password
        .as_ref()
        .map(|s| interpolate_env(s.expose().as_str()))
        .transpose()?;
    match (user, pass) {
        (Some(u), Some(p)) => Ok(mcpg_plugin_host::oci::OciAuth::Basic {
            username: u,
            password: p,
        }),
        (None, None) => {
            // Fall through to Docker config.
            let docker_path = auth.docker_config_path.as_deref().map(std::path::Path::new);
            match mcpg_plugin_host::docker_credentials::resolve_from_docker_config(
                host,
                docker_path,
            ) {
                Ok(Some(oci_auth)) => Ok(oci_auth),
                Ok(None) => Ok(mcpg_plugin_host::oci::OciAuth::Anonymous),
                Err(e) => {
                    // Docker config exists but parsing / helper failed.
                    // Warn and fall through to anonymous rather than hard-fail
                    // — the plugin may be pullable anonymously, and logging
                    // the problem is more useful than a surprise boot refuse.
                    warn!(
                        host = %host,
                        error = %e,
                        "Docker config credential resolution failed; falling back to anonymous"
                    );
                    Ok(mcpg_plugin_host::oci::OciAuth::Anonymous)
                }
            }
        }
        _ => {
            anyhow::bail!(
                "plugin_registry.auth.username and .password must both be set or both unset"
            )
        }
    }
}
