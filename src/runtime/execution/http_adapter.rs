use super::*;

pub(super) fn execute_http_request(
    profile: &str,
    mode: HttpDispatchMode,
    request: &BackendInvocationRequest,
    network_profiles: &std::collections::BTreeMap<String, NetworkToolRuntimeConfig>,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
) -> ToolCallResult {
    let kind = "http";
    if let Some(cancelled) = early_cancel_check(request, profile, kind) {
        return cancelled;
    }

    if !network_profiles.contains_key(profile) {
        return missing_profile_result(request, profile, "network");
    }

    // Tool name as a transport header — the plugin echoes it back in
    // the envelope's `toolName` field. Trace headers are added by
    // `execute_binding_plugin`.
    let plugin = match plugin_registry.and_then(|r| r.backend(kind)) {
        Some(p) => p,
        None => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "HTTP execution for '{}' failed: HTTP backend plugin not registered",
                    request.tool_name
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };

    // Build a request the plugin's payload contract (post or get
    // shape) accepts. POST uses the args verbatim as the JSON body;
    // GET uses the args as the query-string source — the plugin
    // handles both via `HttpBackendMethod` recovered from its
    // registered profile, so the gateway just hands over `arguments`
    // as the payload regardless of mode.
    let _ = mode;

    let args = request.arguments.clone().unwrap_or(serde_json::json!({}));
    let payload = match serde_json::to_vec(&args) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "failed to serialize http request payload: {e}"
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };

    let mut headers = Vec::new();
    if let Some(tc) = request.context.trace_context.as_ref() {
        headers.push(("traceparent".to_owned(), tc.child_traceparent()));
        if let Some(ts) = tc.tracestate.as_deref() {
            headers.push(("tracestate".to_owned(), ts.to_owned()));
        }
    }
    headers.push(("mcpg-tool-name".to_owned(), request.tool_name.clone()));

    let binding_request = mcpg_plugin_protocol::BackendRequest {
        payload,
        headers,
        request_id: request.context.request_id.to_string(),
        session_id: request.context.session_id.clone(),
        identity: Some(crate::runtime::plugin_identity_from_request(
            &request.context,
        )),
        // The HTTP backend lifts the key to the outbound
        // `Idempotency-Key` request header.
        idempotency: request
            .idempotency_hint
            .as_ref()
            .map(|h| h.to_plugin_hint()),
    };

    let profile_owned = profile.to_owned();
    let started = std::time::Instant::now();
    let result = run_async_in_sync_context(plugin.as_ref(), &profile_owned, binding_request);
    let duration_ms = started.elapsed().as_millis() as u64;

    if let Some(registry) = plugin_registry {
        let actor = crate::runtime::plugin_identity_from_request(&request.context);
        let request_id = request.context.request_id.as_str().to_owned();
        let session_id = request.context.session_id.clone();
        let kind_owned = kind.to_owned();
        let profile_owned_for_audit = profile.to_owned();
        let registry_arc = registry.clone();
        let payload_bytes = args.to_string().len() as u64;
        let (success, response_bytes, error_message) = match &result {
            Ok(reply) => (true, reply.payload.len() as u64, None),
            Err(e) => (false, 0u64, Some(e.to_string())),
        };
        let extra_details = plugin.audit_metadata(profile);
        tokio::spawn(async move {
            let event = mcpg_plugin_host::audit_events::backend_executed_event(
                actor,
                &request_id,
                session_id.as_deref(),
                &kind_owned,
                &profile_owned_for_audit,
                success,
                duration_ms,
                payload_bytes,
                response_bytes,
                error_message.as_deref(),
                extra_details,
            );
            let _ = registry_arc.emit_audit_event(&event).await;
        });
    }

    match result {
        Ok(reply) => {
            let reply_text = String::from_utf8_lossy(&reply.payload);
            let structured: Option<serde_json::Value> = serde_json::from_slice(&reply.payload).ok();
            // Treat an envelope-flagged downstream error as a
            // tool-level error so the dispatch retry layer (and
            // operator-visible `is_error`) match the legacy inline
            // path's contract.
            let envelope_is_error = structured
                .as_ref()
                .and_then(|v| v.get("downstreamError"))
                .map(|d| !d.is_null())
                .unwrap_or(false);
            let mut content_text = reply_text.to_string();
            if reply.truncated {
                content_text.push_str("\n[response truncated]");
            }
            ToolCallResult {
                content: vec![ToolContent::text(content_text)],
                structured_content: structured,
                is_error: envelope_is_error,
                meta: Some(binding_audit_meta(kind, profile, envelope_is_error)),
            }
        }
        Err(e) => ToolCallResult {
            content: vec![ToolContent::text(format!("{kind} request failed: {e}"))],
            structured_content: None,
            is_error: true,
            meta: Some(binding_audit_meta(kind, profile, true)),
        },
    }
}

/// Streaming counterpart of [`execute_http_request`]. Routes
/// non-LLM HTTP backend calls through the binding plugin's
/// `execute_streaming` override so the plugin can emit per-chunk
/// `BackendChunk::Progress` events for chunked / SSE / no-
/// Content-Length upstreams.
///
/// Only invoked when the dispatcher gate decided the call is
/// streaming-eligible (HTTP route + `progressToken` set + active
/// session). Buffered upstreams (Content-Length set on the response)
/// emit a single Done at the plugin layer, so the wire-level
/// behaviour matches the buffered path for "small" replies.
pub(super) async fn execute_http_request_streaming(
    profile: &str,
    request: &BackendInvocationRequest,
    network_profiles: &std::collections::BTreeMap<String, NetworkToolRuntimeConfig>,
    plugin_registry: Option<&std::sync::Arc<mcpg_plugin_host::PluginRegistry>>,
    delivery_bus: &Arc<dyn crate::runtime::delivery_bus::DeliveryBus>,
    progress_token: &serde_json::Value,
) -> ToolCallResult {
    let kind = "http";
    if let Some(cancelled) = early_cancel_check(request, profile, kind) {
        return cancelled;
    }
    if !network_profiles.contains_key(profile) {
        return missing_profile_result(request, profile, "network");
    }

    let plugin = match plugin_registry.and_then(|r| r.backend(kind)) {
        Some(p) => p,
        None => {
            return ToolCallResult {
                content: vec![ToolContent::text(format!(
                    "HTTP streaming execution for '{}' failed: HTTP backend plugin not registered",
                    request.tool_name
                ))],
                structured_content: None,
                is_error: true,
                meta: None,
            };
        }
    };

    execute_binding_plugin_streaming(
        kind,
        profile,
        request,
        plugin.as_ref(),
        delivery_bus,
        progress_token,
        plugin_registry,
    )
    .await
}

pub(super) fn prepare_http_call_request(
    call_mode: HttpCallMode,
    arguments: Value,
) -> Result<PreparedHttpCallRequest, String> {
    match call_mode {
        HttpCallMode::JsonBody => Ok(PreparedHttpCallRequest {
            arguments: arguments.clone(),
            request_body: Some(arguments),
            request_query: None,
        }),
        HttpCallMode::QueryString => Ok(PreparedHttpCallRequest {
            request_query: Some(build_http_query_string(&arguments)?),
            arguments,
            request_body: None,
        }),
    }
}

pub(super) fn execute_http_call_request(
    call_mode: HttpCallMode,
    config: &NetworkToolRuntimeConfig,
    prepared_request: &PreparedHttpCallRequest,
    trace_context: Option<&crate::transports::TraceContext>,
) -> Result<NetworkProbeResponse, String> {
    match call_mode {
        HttpCallMode::JsonBody => execute_http_json_call(
            config,
            prepared_request
                .request_body
                .as_ref()
                .expect("JSON body prepared for JSON call"),
            trace_context,
        ),
        HttpCallMode::QueryString => execute_http_query_call(
            config,
            prepared_request
                .request_query
                .as_deref()
                .expect("query string prepared for query call"),
            trace_context,
        ),
    }
}

pub(super) fn build_http_call_structured_content(
    request: &BackendInvocationRequest,
    profile_name: &str,
    network_tool: &NetworkToolRuntimeConfig,
    call_mode: HttpCallMode,
    request_arguments: &Value,
    request_body: Option<&Value>,
    request_query: Option<&str>,
    response: Option<&NetworkProbeResponse>,
    response_json: Option<&Value>,
    response_json_parse_error: Option<&str>,
    downstream_error: Option<&DownstreamHttpError>,
    downstream_errors: &[DownstreamHttpError],
    error: Option<&str>,
) -> Value {
    BackendResultEnvelope {
        tool_name: request.tool_name.clone(),
        profile: profile_name.to_owned(),
        request_kind: call_mode.request_kind().to_owned(),
        request: serde_json::json!({
            "kind": call_mode.request_kind(),
            "arguments": request_arguments,
            "body": request_body,
            "query": request_query,
        }),
        response: response.map(|response| {
            serde_json::json!({
                "durationMs": response.duration_ms,
                "statusCode": response.status_code,
                "contentType": response.content_type,
                "body": response.body,
                "bodyTruncated": response.body_truncated,
                "json": response_json,
                "jsonParseError": response_json_parse_error,
            })
        }),
        primary_error_key: "downstreamError".to_owned(),
        primary_error: downstream_error.map(|e| serde_json::to_value(e).expect("serializable")),
        errors_key: "downstreamErrors".to_owned(),
        errors: serde_json::to_value(downstream_errors).expect("serializable"),
        error: error.map(|s| s.to_owned()),
        family_fields: serde_json::json!({
            "url": network_tool.url,
            "timeoutMs": network_tool.timeout_ms,
            "maxResponseBytes": network_tool.max_response_bytes,
            "expectedStatusCodes": network_tool.expected_status_codes,
            "requireJsonResponse": network_tool.require_json_response,
            "requestHeaders": network_tool.headers,
            "requestArguments": request_arguments,
            "requestBody": request_body,
            "requestQuery": request_query,
            "durationMs": response.map(|r| r.duration_ms),
            "statusCode": response.map(|r| r.status_code),
            "responseContentType": response.and_then(|r| r.content_type.as_deref()),
            "body": response.map(|r| r.body.as_str()),
            "bodyTruncated": response.map(|r| r.body_truncated),
            "responseJson": response_json,
            "responseJsonParseError": response_json_parse_error,
        }),
    }
    .into_value()
}

pub(super) fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

#[derive(Debug)]
pub(super) struct NetworkProbeResponse {
    pub(super) status_code: u16,
    pub(super) content_type: Option<String>,
    pub(super) retry_after_ms: Option<u64>,
    pub(super) body: String,
    pub(super) body_truncated: bool,
    pub(super) duration_ms: u128,
}

pub(super) fn execute_http_probe(
    config: &NetworkToolRuntimeConfig,
    cancel: Option<&tokio_util::sync::CancellationToken>,
) -> Result<NetworkProbeResponse, String> {
    let started_at = Instant::now();
    let parsed = ParsedHttpUrl::parse(&config.url)?;
    let connect_timeout = Duration::from_millis(config.timeout_ms);
    let address = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "failed to resolve debug network URL".to_owned())?;
    // DNS rebinding guard — reject private IPs unless opted in.
    super::safe_dns::validate_resolved_address(
        &address,
        &parsed.host,
        config.allow_private_backends,
    )?;
    if token_cancelled(cancel) {
        return Err("cancelled before connect".to_owned());
    }
    let mut stream =
        TcpStream::connect_timeout(&address, connect_timeout).map_err(|error| error.to_string())?;
    // use a short per-read timeout so the response read loop can
    // poll the cancellation token between chunks rather than blocking
    // for the full config.timeout_ms budget.
    let poll_cadence = Duration::from_millis(config.timeout_ms.clamp(1, 250));
    let _ = stream.set_read_timeout(Some(poll_cadence));
    let _ = stream.set_write_timeout(Some(connect_timeout));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n{}\r\n",
        parsed.path,
        parsed.host,
        format_request_headers(&config.headers, false, 0, None)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;

    let overall_deadline = started_at + connect_timeout;
    let (status_code, content_type, retry_after_ms, body, truncated) =
        read_http_response_with_body_limit_inner(
            stream,
            config.max_response_bytes,
            cancel,
            overall_deadline,
        )
        .map_err(|error| error.to_string())?;

    Ok(NetworkProbeResponse {
        status_code,
        content_type,
        retry_after_ms,
        body,
        body_truncated: truncated,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

pub(super) fn execute_http_json_call(
    config: &NetworkToolRuntimeConfig,
    request_body: &Value,
    trace_context: Option<&crate::transports::TraceContext>,
) -> Result<NetworkProbeResponse, String> {
    let started_at = Instant::now();
    let parsed = ParsedHttpUrl::parse(&config.url)?;
    let connect_timeout = Duration::from_millis(config.timeout_ms);
    let address = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "failed to resolve debug network URL".to_owned())?;
    // DNS rebinding guard.
    super::safe_dns::validate_resolved_address(
        &address,
        &parsed.host,
        config.allow_private_backends,
    )?;
    let mut stream =
        TcpStream::connect_timeout(&address, connect_timeout).map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(connect_timeout));
    let _ = stream.set_write_timeout(Some(connect_timeout));
    let request_body = serde_json::to_string(request_body).map_err(|error| error.to_string())?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{}",
        parsed.path,
        parsed.host,
        request_body.len(),
        format_request_headers(&config.headers, true, request_body.len(), trace_context),
        request_body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;

    let (status_code, content_type, retry_after_ms, body, truncated) =
        read_http_response_with_body_limit(stream, config.max_response_bytes)
            .map_err(|error| error.to_string())?;

    Ok(NetworkProbeResponse {
        status_code,
        content_type,
        retry_after_ms,
        body,
        body_truncated: truncated,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

pub(super) fn execute_http_query_call(
    config: &NetworkToolRuntimeConfig,
    request_query: &str,
    trace_context: Option<&crate::transports::TraceContext>,
) -> Result<NetworkProbeResponse, String> {
    let started_at = Instant::now();
    let parsed = ParsedHttpUrl::parse(&config.url)?;
    let connect_timeout = Duration::from_millis(config.timeout_ms);
    let address = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "failed to resolve debug network URL".to_owned())?;
    // DNS rebinding guard.
    super::safe_dns::validate_resolved_address(
        &address,
        &parsed.host,
        config.allow_private_backends,
    )?;
    let mut stream =
        TcpStream::connect_timeout(&address, connect_timeout).map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(connect_timeout));
    let _ = stream.set_write_timeout(Some(connect_timeout));
    let request_path = with_query_string(&parsed.path, request_query);
    let accept_header = if config.require_json_response {
        "application/json"
    } else {
        "*/*"
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: {}\r\n{}\r\n",
        request_path,
        parsed.host,
        accept_header,
        format_request_headers(&config.headers, false, 0, trace_context)
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;

    let (status_code, content_type, retry_after_ms, body, truncated) =
        read_http_response_with_body_limit(stream, config.max_response_bytes)
            .map_err(|error| error.to_string())?;

    Ok(NetworkProbeResponse {
        status_code,
        content_type,
        retry_after_ms,
        body,
        body_truncated: truncated,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

pub(super) fn build_http_query_string(arguments: &Value) -> Result<String, String> {
    let Value::Object(object) = arguments else {
        return Err("network query call arguments must be a JSON object".to_owned());
    };

    let mut keys = object.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    let mut pairs = Vec::new();

    for key in keys {
        let value = object
            .get(&key)
            .expect("query call key looked up from object keys");
        append_query_pairs(&mut pairs, &key, value)?;
    }

    Ok(pairs.join("&"))
}

pub(super) fn append_query_pairs(
    pairs: &mut Vec<String>,
    key: &str,
    value: &Value,
) -> Result<(), String> {
    match value {
        Value::Array(items) => {
            for item in items {
                pairs.push(format!(
                    "{}={}",
                    percent_encode_component(key),
                    percent_encode_component(&query_value_string(item)?)
                ));
            }
            Ok(())
        }
        _ => {
            pairs.push(format!(
                "{}={}",
                percent_encode_component(key),
                percent_encode_component(&query_value_string(value)?)
            ));
            Ok(())
        }
    }
}

pub(super) fn query_value_string(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::String(string) => Ok(string.clone()),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).map_err(|error| error.to_string())
        }
    }
}

pub(super) fn percent_encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{:02X}", byte));
        }
    }
    encoded
}

pub(super) fn with_query_string(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_owned()
    } else if path.contains('?') {
        format!("{path}&{query}")
    } else {
        format!("{path}?{query}")
    }
}

pub(super) fn format_request_headers(
    headers: &std::collections::BTreeMap<String, String>,
    is_json_call: bool,
    _content_length: usize,
    trace_context: Option<&crate::transports::TraceContext>,
) -> String {
    let mut lines = Vec::new();
    for (name, value) in headers {
        if is_protected_request_header(name, is_json_call) {
            continue;
        }
        // token-passthrough guard. Reject credential-shaped
        // values unless the operator has explicitly opted in via the
        // `feature_flags.allow_header_passthrough` escape hatch. An operator
        // that accidentally wires an inbound bearer through the
        // gateway's egress should not silently leak it to the
        // upstream binding.
        if is_credential_header(name) && !crate::runtime::feature_flags::allow_header_passthrough()
        {
            metrics::counter!(
                "mcpg_credential_header_stripped_total",
                "header" => name.to_ascii_lowercase(),
            )
            .increment(1);
            tracing::warn!(
                header = %name,
                "credential-shaped request header stripped at egress; \
                 set feature_flags.allow_header_passthrough: true in your \
                 config only for deployments that intentionally \
                 forward client tokens"
            );
            continue;
        }
        lines.push(format!("{}: {}\r\n", name, value));
    }
    // Inject W3C trace context headers for distributed tracing
    if let Some(tc) = trace_context {
        lines.push(format!("traceparent: {}\r\n", tc.child_traceparent()));
        if let Some(ref ts) = tc.tracestate {
            lines.push(format!("tracestate: {}\r\n", ts));
        }
    }
    lines.concat()
}

pub(super) fn is_protected_request_header(name: &str, is_json_call: bool) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(lower.as_str(), "host" | "connection" | "content-length")
        || (is_json_call && matches!(lower.as_str(), "accept" | "content-type"))
        // strip hop-by-hop and forwarding headers so the
        // gateway does not leak client IP / proxy topology to the
        // upstream backend.
        || lower.starts_with("x-forwarded-")
        || matches!(
            lower.as_str(),
            "forwarded" | "via" | "x-real-ip" | "x-request-id"
        )
}

/// headers whose values are credentials we never want to
/// passthrough to operator-configured backends by default. Shares the
/// redactor's canonical [`CREDENTIAL_KEYS`] list so the two surfaces
/// can't drift.
///
/// [`CREDENTIAL_KEYS`]: crate::runtime::redact::CREDENTIAL_KEYS
pub(super) fn is_credential_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    crate::runtime::redact::CREDENTIAL_KEYS
        .iter()
        .any(|needle| lower.eq_ignore_ascii_case(needle))
}

/// Backwards-compatible entry point for HTTP callers that do not yet
/// plumb a cancellation token. Uses a 2-minute conservative deadline so
/// calls bound by their own `timeout_ms` still behave as before.
pub(super) fn read_http_response_with_body_limit(
    stream: TcpStream,
    body_limit: usize,
) -> Result<(u16, Option<String>, Option<u64>, String, bool), std::io::Error> {
    read_http_response_with_body_limit_inner(
        stream,
        body_limit,
        None,
        Instant::now() + Duration::from_secs(120),
    )
}

pub(super) fn read_http_response_with_body_limit_inner(
    mut stream: TcpStream,
    body_limit: usize,
    cancel: Option<&tokio_util::sync::CancellationToken>,
    overall_deadline: Instant,
) -> Result<(u16, Option<String>, Option<u64>, String, bool), std::io::Error> {
    const MAX_HEADER_BYTES: usize = 8_192;

    // wrap `stream.read` with cancellation + wall-clock checks.
    // The stream is configured with a short `read_timeout` so a blocked
    // read returns `WouldBlock` / `TimedOut` frequently, letting this
    // helper decide whether to (a) drop out due to cancellation, (b)
    // drop out due to the overall deadline, or (c) keep reading.
    fn read_with_poll(
        stream: &mut TcpStream,
        buffer: &mut [u8],
        cancel: Option<&tokio_util::sync::CancellationToken>,
        overall_deadline: Instant,
    ) -> Result<usize, std::io::Error> {
        loop {
            if token_cancelled(cancel) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "HTTP read cancelled",
                ));
            }
            if Instant::now() >= overall_deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP read exceeded overall timeout",
                ));
            }
            match stream.read(buffer) {
                Ok(n) => return Ok(n),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = read_with_poll(&mut stream, &mut buffer, cancel, overall_deadline)?;
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "incomplete HTTP response headers",
            ));
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > MAX_HEADER_BYTES
            && !response.windows(4).any(|window| window == b"\r\n\r\n")
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP response headers exceed limit",
            ));
        }
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let head = String::from_utf8_lossy(&response[..header_end]).to_string();
    let status_line = head.lines().next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP status line")
    })?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP status code")
        })?
        .parse::<u16>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let content_type = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-type") {
            Some(value.trim().to_owned())
        } else {
            None
        }
    });
    let retry_after_ms = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("retry-after") {
            parse_retry_after_ms(value.trim())
        } else {
            None
        }
    });

    let mut body = Vec::new();
    let mut truncated = false;
    append_limited_bytes(
        &mut body,
        &response[header_end..],
        body_limit,
        &mut truncated,
    );

    loop {
        let count = read_with_poll(&mut stream, &mut buffer, cancel, overall_deadline)?;
        if count == 0 {
            break;
        }
        append_limited_bytes(&mut body, &buffer[..count], body_limit, &mut truncated);
    }

    Ok((
        status_code,
        content_type,
        retry_after_ms,
        String::from_utf8_lossy(&body).to_string(),
        truncated,
    ))
}

pub(super) fn append_limited_bytes(
    target: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
    truncated: &mut bool,
) {
    if target.len() < limit {
        let remaining = limit - target.len();
        let copy_len = remaining.min(chunk.len());
        target.extend_from_slice(&chunk[..copy_len]);
        if chunk.len() > copy_len {
            *truncated = true;
        }
    } else if !chunk.is_empty() {
        *truncated = true;
    }
}

#[derive(Debug)]
pub(super) struct ParsedHttpUrl {
    host: String,
    port: u16,
    path: String,
}

impl ParsedHttpUrl {
    fn parse(url: &str) -> Result<Self, String> {
        let without_scheme = url
            .strip_prefix("http://")
            .ok_or_else(|| "only http:// URLs are supported".to_owned())?;
        let (host_port, path_suffix) = match without_scheme.split_once('/') {
            Some((host_port, path)) => (host_port, format!("/{path}")),
            None => (without_scheme, "/".to_owned()),
        };
        let (host, port) = match host_port.split_once(':') {
            Some((host, port)) => (
                host.to_owned(),
                port.parse::<u16>().map_err(|error| error.to_string())?,
            ),
            None => (host_port.to_owned(), 80),
        };

        if host.trim().is_empty() {
            return Err("missing host in debug network URL".to_owned());
        }

        Ok(Self {
            host,
            port,
            path: path_suffix,
        })
    }
}
