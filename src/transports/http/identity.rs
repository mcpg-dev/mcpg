//! Request-identity resolution for the HTTP transport.
//!
//! Turns raw headers (bearer token, mTLS peer cert, asserted subject) into a
//! [`RequestContext`] by running the identity-plugin chain, then falls back to
//! a header-asserted or anonymous principal. Carries no MCP-specific logic —
//! `transports::http_route` uses the same entry point for plugin HTTP routes.

use super::*;

/// Build a request context with full identity resolution: transport-level + plugin chain.
///
/// `tls_info` should be the per-connection TLS metadata stamped onto
/// the request by the [`crate::transports::tls`] acceptor; pass
/// `None` for plain HTTP requests. The metadata threads through to
/// `RequestMetadata.tls` so identity plugins like `dev.mcpg.identity.workload`'s
/// X.509-SVID source can consume the peer cert chain.
pub(crate) async fn build_full_request_context(
    headers: &HeaderMap,
    runtime: &crate::runtime::GatewayRuntime,
    tls_info: Option<crate::transports::tls::TlsInfoArc>,
    trust_subject_header: bool,
    method: &axum::http::Method,
    path: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<RequestContext, Response> {
    let ctx = build_request_context(
        headers,
        runtime.jwt_verifier(),
        runtime.oidc_resolver(),
        runtime.ema_authorization_server(),
        Some(runtime.plugin_registry()),
        trust_subject_header,
        peer_ip,
    )
    .await?;
    let ctx = enrich_identity_via_plugins(
        ctx,
        headers,
        runtime.plugin_registry(),
        tls_info,
        method,
        path,
    )
    .await?;
    enforce_aauth_resource_state(ctx, runtime).await
}

/// The gateway's AAuth resource role, applied after the identity chain: a
/// credential its issuer revoked at our revocation endpoint is refused
/// (401 + `Signature-Error: error=invalid_jwt`, the code the identity plugin
/// uses for a config-listed revocation), and a verified person token is
/// remembered so a later auth-token step-up can name it.
async fn enforce_aauth_resource_state(
    ctx: RequestContext,
    runtime: &crate::runtime::GatewayRuntime,
) -> Result<RequestContext, Response> {
    let Some(resource) = runtime.aauth_resource() else {
        return Ok(ctx);
    };
    if resource.is_revoked(&ctx.identity) {
        tracing::warn!(
            request_id = %ctx.request_id.as_str(),
            issuer = ?ctx.identity.issuer(),
            "AAuth credential revoked by its issuer, rejecting with 401"
        );
        let event = mcpg_plugin_host::audit_events::auth_failed_event(
            "aauth",
            "credential revoked by its issuer",
            ctx.request_id.as_str(),
            "http",
        );
        let _ = runtime.plugin_registry().emit_audit_event(&event).await;
        return Err(invalid_token_response_with_headers(
            &ctx.request_id,
            &[("signature-error".to_owned(), "error=invalid_jwt".to_owned())],
        ));
    }
    resource.record_identity(&ctx.identity);
    Ok(ctx)
}

pub(crate) async fn build_request_context(
    headers: &HeaderMap,
    jwt_verifier: Option<&crate::runtime::identity::JwtVerifier>,
    oidc_resolver: Option<&crate::runtime::oidc::OidcOAuthResolver>,
    ema_authorization_server: Option<&crate::runtime::authorization_server::AuthorizationServer>,
    audit_registry: Option<&mcpg_plugin_host::PluginRegistry>,
    trust_subject_header: bool,
    peer_ip: Option<std::net::IpAddr>,
) -> Result<RequestContext, Response> {
    let request_id = GatewayRequestId::new();
    let upstream_request_id = headers
        .get(UPSTREAM_REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let session_id = headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let resume_cursor = headers
        .get(LAST_EVENT_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(|last_event_id| ResumeCursor {
            last_event_id: last_event_id.to_owned(),
        });

    // Identity resolution priority:
    // 0. Gateway-minted EMA access tokens (embedded authorization server)
    // 1. OIDC/OAuth (enterprise identity) — async, supports discovery/introspection
    // 2. JWKS (legacy JWT verification) — sync
    // 3. Header-asserted
    // 4. Anonymous
    //
    // A bearer whose `iss` names the embedded EMA authorization server
    // MUST verify there — once a token claims to be gateway-minted it
    // never falls through to another verifier, so a forgery cannot
    // shop for a laxer validation path.
    let ema_identity = match (ema_authorization_server, extract_inbound_bearer(headers)) {
        (Some(ema), Some(bearer)) => match ema.verify_bearer(&bearer) {
            crate::runtime::authorization_server::EmaBearerOutcome::NotOurs => None,
            crate::runtime::authorization_server::EmaBearerOutcome::Verified(id) => {
                Some(RequestIdentity::Verified {
                    subject_id: id.subject_id,
                    issuer: id.issuer,
                    auth_provider: "ema".to_owned(),
                    source: "authorization:ema_access_token".to_owned(),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: id.scopes,
                    attributes: id.attributes,
                })
            }
            crate::runtime::authorization_server::EmaBearerOutcome::Invalid(reason) => {
                tracing::warn!(
                    request_id = %request_id.as_str(),
                    reason = %reason,
                    "EMA access token verification failed, rejecting with 401"
                );
                if let Some(reg) = audit_registry {
                    let event = mcpg_plugin_host::audit_events::auth_failed_event(
                        "ema",
                        &reason,
                        request_id.as_str(),
                        "http",
                    );
                    let _ = reg.emit_audit_event(&event).await;
                }
                return Err(invalid_token_response(&request_id));
            }
        },
        _ => None,
    };
    // Priority -1: the supervised inspector's process-minted loopback
    // credential (see `runtime::inspector_identity`). Checked before
    // every verifier for the same reason as the EMA arm: the token is
    // gateway-minted, so it must never fall through to a verifier
    // that would reject it as a foreign bearer.
    let inspector_identity = crate::runtime::inspector_identity::verify(
        extract_inbound_bearer(headers).as_deref(),
        peer_ip,
    );

    let identity = if let Some(identity) = inspector_identity {
        identity
    } else if let Some(identity) = ema_identity {
        identity
    } else if let Some(resolver) = oidc_resolver {
        match resolver.verify_from_headers(headers).await {
            crate::runtime::oidc::OidcVerificationResult::Verified(oidc_id) => {
                RequestIdentity::Verified {
                    subject_id: oidc_id.subject_id,
                    issuer: oidc_id.issuer,
                    auth_provider: format!("oidc_oauth:{}", oidc_id.provider_label),
                    source: format!("{}:oidc_oauth", resolver.header_name()),
                    roles: oidc_id.roles,
                    groups: oidc_id.groups,
                    scopes: oidc_id.scopes,
                    attributes: oidc_id.attributes,
                }
            }
            crate::runtime::oidc::OidcVerificationResult::Invalid(reason) => {
                // A credential WAS presented and FAILED verification
                // (`None` is the no-credential case). Fail closed with
                // HTTP 401 — never silently downgrade a forged/expired
                // token to a header-asserted or anonymous identity.
                tracing::warn!(
                    request_id = %request_id.as_str(),
                    reason = %reason,
                    "OIDC/OAuth verification failed, rejecting with 401"
                );
                // Audit: failed auth attempt on record
                // per SOC2 / HIPAA failed-login dashboards.
                if let Some(reg) = audit_registry {
                    let event = mcpg_plugin_host::audit_events::auth_failed_event(
                        "oidc",
                        &reason,
                        request_id.as_str(),
                        "http",
                    );
                    let _ = reg.emit_audit_event(&event).await;
                }
                return Err(invalid_token_response(&request_id));
            }
            crate::runtime::oidc::OidcVerificationResult::None => {
                build_header_or_anonymous_identity(headers, trust_subject_header)
            }
        }
    } else if let Some(verifier) = jwt_verifier {
        match verifier.verify_from_headers(headers) {
            crate::runtime::identity::JwtVerificationResult::Verified { subject, issuer } => {
                RequestIdentity::Verified {
                    subject_id: subject,
                    issuer: issuer.unwrap_or_default(),
                    auth_provider: "jwks".to_owned(),
                    source: format!("{}:{}", verifier.header_name(), "jwt"),
                    roles: Vec::new(),
                    groups: Vec::new(),
                    scopes: Vec::new(),
                    attributes: std::collections::BTreeMap::new(),
                }
            }
            crate::runtime::identity::JwtVerificationResult::Invalid(reason) => {
                // Credential presented and FAILED verification — fail
                // closed with 401 (see the OIDC arm above).
                tracing::warn!(
                    request_id = %request_id.as_str(),
                    reason = %reason,
                    "JWT verification failed, rejecting with 401"
                );
                // Audit: failed auth attempt on record.
                if let Some(reg) = audit_registry {
                    let event = mcpg_plugin_host::audit_events::auth_failed_event(
                        "jwt",
                        &reason,
                        request_id.as_str(),
                        "http",
                    );
                    let _ = reg.emit_audit_event(&event).await;
                }
                return Err(invalid_token_response(&request_id));
            }
            crate::runtime::identity::JwtVerificationResult::None => {
                build_header_or_anonymous_identity(headers, trust_subject_header)
            }
        }
    } else {
        build_header_or_anonymous_identity(headers, trust_subject_header)
    };

    Ok(RequestContext::new(
        request_id,
        upstream_request_id,
        session_id,
        resume_cursor,
        identity,
        TransportKind::Http,
    )
    .with_trace_context(extract_trace_context(headers))
    .with_inbound_bearer(extract_inbound_bearer(headers)))
}

/// Run identity plugin chain and upgrade identity if a plugin resolves.
///
/// Called after the hardcoded identity cascade. If the plugin registry has
/// identity plugins and one resolves a higher-trust identity, it replaces
/// the transport-level identity. This allows operators to wire custom
/// identity providers (e.g. mTLS, API-key, external IdP) via plugins.
async fn enrich_identity_via_plugins(
    mut ctx: RequestContext,
    headers: &HeaderMap,
    registry: &mcpg_plugin_host::PluginRegistry,
    tls_info: Option<crate::transports::tls::TlsInfoArc>,
    method: &axum::http::Method,
    path: Option<&str>,
) -> Result<RequestContext, Response> {
    if !registry.has_identity_plugins() {
        return Ok(ctx);
    }

    // Convert HeaderMap to plugin-friendly (String, String) pairs
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect();

    // Protocol 1.1: thread `RequestMetadata` (including TLS info,
    // when the gateway terminates mTLS) through to the identity
    // chain. `tls_info` is `Some(_)` whenever the connection
    // actually has TLS state (peer cert chain or SNI present);
    // plain HTTP requests + TLS without mTLS leave it absent.
    // `path` arrives as the raw request target (path + optional query); split
    // so `metadata.path` stays query-free and signature-based identity plugins
    // (RFC 9421 / AAuth) can reconstruct `@query` separately.
    let (req_path, req_query) = match path {
        Some(target) => match target.split_once('?') {
            Some((p, q)) => (Some(p.to_owned()), Some(q.to_owned())),
            None => (Some(target.to_owned()), None),
        },
        None => (None, None),
    };
    let metadata = mcpg_plugin_protocol::types::RequestMetadata {
        remote_addr: None,
        tls: tls_info.as_deref().cloned(),
        transport: "http".into(),
        path: req_path,
        // Signature-based identity plugins (RFC 9421 / AAuth) cover `@method`
        // and (optionally) `@query`.
        method: Some(method.as_str().to_owned()),
        query: req_query,
    };
    match registry.resolve_identity(&header_pairs, &metadata).await {
        mcpg_plugin_host::ChainIdentityOutcome::Resolved(plugin_identity) => {
            // Convert PluginIdentity back to RequestIdentity
            ctx.identity = plugin_identity_to_request(&plugin_identity);
        }
        // Nobody recognised a credential — leave whatever the transport
        // cascade established (anonymous, or header-asserted).
        mcpg_plugin_host::ChainIdentityOutcome::NoCredential => {}
        // A plugin rejected the credential the caller presented. Treating
        // that as "no credential" would fail open to anonymous and leave no
        // audit record, so it is refused the same way a bad bearer is on the
        // transport cascade above.
        mcpg_plugin_host::ChainIdentityOutcome::Rejected {
            plugin_id,
            reason,
            response_headers,
        } => {
            tracing::warn!(
                request_id = %ctx.request_id.as_str(),
                plugin_id = %plugin_id,
                reason = %reason,
                "identity plugin rejected the presented credential, rejecting with 401"
            );
            let event = mcpg_plugin_host::audit_events::auth_failed_event(
                &plugin_id,
                &reason,
                ctx.request_id.as_str(),
                "http",
            );
            let _ = registry.emit_audit_event(&event).await;
            return Err(invalid_token_response_with_headers(
                &ctx.request_id,
                &response_headers,
            ));
        }
    }

    Ok(ctx)
}

/// Convert a `PluginIdentity` resolved by the plugin chain back to a `RequestIdentity`.
pub(crate) fn plugin_identity_to_request(
    pi: &mcpg_plugin_protocol::PluginIdentity,
) -> RequestIdentity {
    match pi.trust_level.as_str() {
        "verified" => RequestIdentity::Verified {
            subject_id: pi.subject_id.clone().unwrap_or_default(),
            issuer: pi.issuer.clone().unwrap_or_default(),
            auth_provider: pi.auth_provider.clone().unwrap_or_default(),
            source: format!("identity_plugin:{}", pi.kind),
            roles: pi.roles.clone(),
            groups: pi.groups.clone(),
            scopes: pi.scopes.clone(),
            attributes: pi.attributes.clone(),
        },
        "header_asserted" => RequestIdentity::HttpHeader {
            subject_id: pi.subject_id.clone().unwrap_or_default(),
            source: format!("identity_plugin:{}", pi.kind),
        },
        _ => RequestIdentity::Anonymous {
            source: "identity_plugin:no_resolution".into(),
        },
    }
}

/// Extract the inbound bearer token (strips the `Bearer ` scheme) for
/// `auth.mode: pass_through` federation dispatch. Non-Bearer
/// Authorization schemes are not forwarded.
fn extract_inbound_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::to_owned)
}

fn extract_trace_context(headers: &HeaderMap) -> Option<crate::transports::TraceContext> {
    let traceparent = headers.get("traceparent").and_then(|v| v.to_str().ok())?;
    let tracestate = headers.get("tracestate").and_then(|v| v.to_str().ok());
    crate::transports::TraceContext::parse(traceparent, tracestate)
}

/// Resolve a header-asserted or anonymous identity from the request
/// headers, used only when no credential was presented to a configured
/// verifier (or none is configured). The `x-mcpg-subject-id` header
/// carries no proof of the caller, so it is honoured ONLY when the
/// operator opted in via `server.trust_subject_header` (i.e. a trusted
/// upstream authenticates the caller and injects the header). When the
/// flag is false (default) the header is ignored entirely and the
/// request resolves to Anonymous.
fn build_header_or_anonymous_identity(
    headers: &HeaderMap,
    trust_subject_header: bool,
) -> RequestIdentity {
    if !trust_subject_header {
        return RequestIdentity::Anonymous {
            source: "subject_header_untrusted".to_owned(),
        };
    }
    headers
        .get(SUBJECT_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(|subject_id| RequestIdentity::HttpHeader {
            subject_id: subject_id.to_owned(),
            source: SUBJECT_ID_HEADER.to_owned(),
        })
        .unwrap_or_else(|| RequestIdentity::Anonymous {
            source: "no_subject_header".to_owned(),
        })
}

/// HTTP 401 response for a presented-but-invalid bearer credential
/// (forged / expired / wrong-issuer / bad-signature). Fails closed at
/// the transport boundary rather than downgrading to a lower-trust
/// identity. Carries a JSON-RPC error envelope (id `null`, JSON-RPC
/// §5.1) plus the standard `WWW-Authenticate: Bearer` challenge and the
/// gateway request-id echo header.
fn invalid_token_response(request_id: &GatewayRequestId) -> Response {
    invalid_token_response_with_headers(request_id, &[])
}

/// As [`invalid_token_response`], additionally attaching plugin-supplied
/// diagnostic headers — e.g. AAuth's `Signature-Error` (the machine-readable
/// error channel) and `Accept-Signature-Scheme` / `Accept-Signature-Alg`
/// (what WOULD succeed). Header names/values that fail HTTP validation are
/// dropped individually rather than failing the response.
fn invalid_token_response_with_headers(
    request_id: &GatewayRequestId,
    extra_headers: &[(String, String)],
) -> Response {
    let mut resp = (
        axum::http::StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            "Bearer error=\"invalid_token\"",
        )],
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            // Impl-defined band (`-32000..-32019`); kept out of the
            // `2026-07-28` MCP-reserved band (`-32020..-32099`).
            "error": {
                "code": -32000,
                "message": "authentication failed: invalid or expired credential",
            },
        })),
    )
        .into_response();
    for (name, value) in extra_headers {
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::try_from(name.as_str()),
            axum::http::HeaderValue::try_from(value.as_str()),
        ) {
            resp.headers_mut().append(n, v);
        }
    }
    with_request_id_header(resp, request_id)
}

/// SEP-2133 `dev.mcpg/idempotency` HTTP-transport lift.
///
/// When the request carries an `Idempotency-Key` HTTP header but
/// the JSON-RPC body's `params._meta["dev.mcpg/idempotency-key"]`
/// field is absent, promote the header value into `_meta` so the
/// downstream dispatcher can dedupe over a stdio-/HTTP-uniform
/// code path. Header value is validated with the same constraints
/// as the `_meta` field (ASCII / ≤255 / non-empty) — malformed
/// values short-circuit with HTTP 400 + `-32013
/// IdempotencyKeyMalformed` before any further processing.
///
/// Per design doc §1.4 the explicit `_meta` field always wins on
/// conflict (Stripe-style precedence): when both surfaces carry a
/// value, the body's value is the effective key and the header is
/// silently ignored.
pub(crate) fn lift_idempotency_key_header(
    mut body: Value,
    headers: &HeaderMap,
    request_id: &GatewayRequestId,
) -> Result<Value, Response> {
    // RFC `draft-ietf-httpapi-idempotency-key-header-07` defines
    // the canonical name as `Idempotency-Key`. HTTP header lookup
    // is case-insensitive (axum/hyper normalise to lower-case
    // internally), so a single `.get` covers every casing.
    let header_value = headers.get("idempotency-key").and_then(|v| v.to_str().ok());
    let Some(header_str) = header_value else {
        return Ok(body);
    };
    // Validate format — same constraints as the body path.
    let validation = crate::runtime::idempotency::validate_request_key(Some(&Value::String(
        header_str.to_owned(),
    )));
    let header_key = match validation {
        crate::runtime::idempotency::KeyValidation::Valid(k) => k,
        crate::runtime::idempotency::KeyValidation::Absent => {
            // Empty `Idempotency-Key:` header — treat as absent.
            return Ok(body);
        }
        crate::runtime::idempotency::KeyValidation::Invalid(reason) => {
            // Synthesise a JSON-RPC error response directly —
            // `ProtocolError` constructors don't expose the
            // `-32013` code we need. The body's `id` is unknown
            // at this stage (we haven't parsed it yet), so the
            // error envelope's `id` is `null` per JSON-RPC §5.1.
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": crate::runtime::idempotency::ERROR_CODE_KEY_MALFORMED,
                    "message": reason.as_message(),
                }
            });
            let resp = (axum::http::StatusCode::BAD_REQUEST, axum::Json(body)).into_response();
            return Err(with_request_id_header(resp, request_id));
        }
    };
    // Stripe-style precedence: explicit `_meta` value wins.
    if let Some(params) = body.get("params").and_then(Value::as_object)
        && let Some(meta) = params.get("_meta").and_then(Value::as_object)
        && meta.contains_key(crate::runtime::idempotency::META_KEY_REQUEST)
    {
        return Ok(body);
    }
    let Some(body_obj) = body.as_object_mut() else {
        return Ok(body);
    };
    let params = body_obj
        .entry("params")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(params_obj) = params.as_object_mut() else {
        return Ok(body);
    };
    let meta = params_obj
        .entry("_meta")
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(meta_obj) = meta.as_object_mut() else {
        return Ok(body);
    };
    meta_obj.insert(
        crate::runtime::idempotency::META_KEY_REQUEST.to_owned(),
        Value::String(header_key),
    );
    Ok(body)
}
