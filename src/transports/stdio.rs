//! Stdio transport for MCPG.
//!
//! Reads newline-delimited JSON-RPC messages from stdin, writes responses to stdout.
//! Single-session: no session ID needed. Designed for local MCP clients (IDEs, CLI tools).
//!
//! Supports bidirectional push: after session initialization, server-to-client
//! notifications and requests arrive via the DeliveryBus and are written to stdout.

use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::app::AppState;
use crate::protocol::{ProtocolResponse, map_client_message_to_operation, parse_client_message};
use crate::runtime::{
    GatewayOperation, GatewayRequest, GatewayRequestId, GatewayResponsePayload, RequestContext,
    RequestIdentity, ResumeCursor, TransportKind, pipeline_store::DeliveryMessage,
};

/// Run the stdio transport. Reads from stdin, writes to stdout. Blocks until stdin closes.
pub async fn serve(state: AppState, mut shutdown: tokio::sync::watch::Receiver<()>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = stdout;
    let mut line = String::new();
    let mut session_id: Option<String> = None;
    // Delivery bus receiver for server-to-client push (set after session init).
    let mut delivery_rx: Option<mpsc::Receiver<DeliveryMessage>> = None;

    info!("stdio transport ready, reading from stdin");

    loop {
        line.clear();

        // Read one line, or exit on shutdown / EOF / delivery bus message
        enum StdioEvent {
            StdinLine(std::io::Result<usize>),
            Shutdown,
            Delivery(DeliveryMessage),
        }

        let event = tokio::select! {
            result = reader.read_line(&mut line) => StdioEvent::StdinLine(result),
            _ = shutdown.changed() => StdioEvent::Shutdown,
            Some(msg) = async {
                match delivery_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<DeliveryMessage>>().await,
                }
            } => StdioEvent::Delivery(msg),
        };

        match event {
            StdioEvent::Shutdown => {
                info!("stdio transport received shutdown signal");
                break;
            }
            StdioEvent::Delivery(msg) => {
                // Server-to-client push: write the delivery message to stdout.
                debug!(kind = ?msg.kind, "delivering server-initiated message to stdio client");
                write_json_line(&mut writer, &msg.jsonrpc_message).await?;
                continue;
            }
            StdioEvent::StdinLine(result) => {
                let bytes_read = match result {
                    Ok(n) => n,
                    Err(e) => {
                        error!(error = %e, "stdin read error");
                        break;
                    }
                };
                if bytes_read == 0 {
                    info!("stdin closed (EOF)");
                    break;
                }
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!(line = %trimmed, "received message from stdin");

        // Parse JSON
        let body: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let error_response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("parse error: {e}")
                    }
                });
                write_json_line(&mut writer, &error_response).await?;
                continue;
            }
        };

        // Parse JSON-RPC client message
        let client_message = match parse_client_message(body) {
            Ok(msg) => msg,
            Err(protocol_error) => {
                let error_json = serde_json::to_value(protocol_error.into_jsonrpc_error())
                    .expect("serialize error");
                write_json_line(&mut writer, &error_json).await?;
                continue;
            }
        };

        // Map to a protocol operation. Stdio does not carry MCP-Protocol-Version
        // headers; the transport is a single trusted process and always speaks the
        // one supported spec revision.
        let operation = match map_client_message_to_operation(client_message) {
            Ok(op) => op,
            Err(protocol_error) => {
                let error_json = serde_json::to_value(protocol_error.into_jsonrpc_error())
                    .expect("serialize error");
                write_json_line(&mut writer, &error_json).await?;
                continue;
            }
        };

        // Build request context.
        //
        // stdio is intentionally identity-plugin-less. Identity plugins
        // (OIDC, JWT, header-asserted, ...) resolve a remote principal from
        // HTTP request headers / bearer tokens. Over stdio there is no wire
        // credential: the caller is the OS process that owns the fd pair, and
        // authorization is expressed by which binary was allowed to spawn
        // MCPG in the first place. Introducing the HTTP identity-plugin
        // chain here would either be a no-op (no headers to evaluate) or
        // actively misleading (every request would appear to be the same
        // header-asserted subject). Stdio therefore stays anonymous-by-default
        // and expects the surrounding process boundary to supply trust.
        let identity = RequestIdentity::Anonymous {
            source: "stdio".to_owned(),
        };
        let request_context = RequestContext::new(
            GatewayRequestId::new(),
            None,
            session_id.clone(),
            None::<ResumeCursor>,
            identity,
            TransportKind::Stdio,
        );

        let request = GatewayRequest::new(request_context, GatewayOperation::Protocol(operation));

        let runtime = state.runtime.load();
        let response = runtime.handle_request(request).await;

        // Extract session ID from initialize response and subscribe to delivery bus.
        if let GatewayResponsePayload::Protocol(ref protocol_response) = response.payload
            && let Some(ref sid) = protocol_response.session_id_header
            && (session_id.is_none() || session_id.as_deref() != Some(sid.as_str()))
        {
            session_id = Some(sid.clone());
            // Subscribe to delivery bus for server-to-client push.
            delivery_rx = Some(runtime.subscribe_session_delivery(sid).await);
            info!(session_id = %sid, "session established, delivery bus subscribed");
        }

        // Write response to stdout
        match response.payload {
            GatewayResponsePayload::Protocol(protocol_response) => {
                match protocol_response.response {
                    ProtocolResponse::JsonRpcSuccess(success) => {
                        let json = serde_json::to_value(&success).expect("serialize success");
                        write_json_line(&mut writer, &json).await?;
                    }
                    ProtocolResponse::JsonRpcError(error) => {
                        let json = serde_json::to_value(&error).expect("serialize error");
                        write_json_line(&mut writer, &json).await?;
                    }
                    ProtocolResponse::NotificationAccepted => {
                        // Notifications don't get a response in stdio mode
                        debug!("notification accepted (no response)");
                    }
                }
            }
            GatewayResponsePayload::Readiness(snapshot) => {
                let json = serde_json::to_value(&snapshot).expect("serialize readiness");
                write_json_line(&mut writer, &json).await?;
            }
            GatewayResponsePayload::Runtime(snapshot) => {
                let json = serde_json::to_value(&snapshot).expect("serialize runtime");
                write_json_line(&mut writer, &json).await?;
            }
        }
    }

    info!("stdio transport stopped");
    Ok(())
}

async fn write_json_line(writer: &mut tokio::io::Stdout, value: &Value) -> Result<()> {
    let mut output = serde_json::to_string(value)?;
    output.push('\n');
    writer.write_all(output.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_format_is_newline_terminated() {
        let value = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}});
        let mut output = serde_json::to_string(&value).unwrap();
        output.push('\n');
        assert!(output.ends_with('\n'));
        assert!(serde_json::from_str::<Value>(output.trim()).is_ok());
    }
}
