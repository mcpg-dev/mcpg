//! Stdio transport for MCPG.
//!
//! Reads newline-delimited JSON-RPC messages from stdin and writes each
//! answer to stdout as one JSON line. It speaks MCP 2026-07-28: a message
//! names that revision in its `_meta`, or names none.
//!
//! The process is one client, so the transport opens one session when it
//! starts and runs every request under it. Each message goes through the same
//! dispatch as an HTTP request ([`crate::transports::dispatch`]). A
//! `subscriptions/listen` stream writes its frames to stdout between answers
//! until the session ends or the client cancels the listen request with
//! `notifications/cancelled`; `events/stream` is served on HTTP only.

use anyhow::Result;
use futures::StreamExt as _;
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::app::AppState;
use crate::protocol::{ProtocolError, ProtocolHttpResponse, ProtocolResponse, StreamPlan};
use crate::runtime::{GatewayRequestId, RequestContext, RequestIdentity, TransportKind};
use crate::transports::dispatch::{DispatchOutcome, dispatch, transport_rejection_body};
use crate::transports::listen::{ListenStream, open_listen};

/// Frames of open `subscriptions/listen` streams that wait for stdout.
const LISTEN_FRAME_BUFFER: usize = 64;

/// The open `subscriptions/listen` streams of the process, keyed by the
/// listen request's JSON-RPC id as serialized, so `1` and `"1"` stay apart.
/// A client has no connection to close on stdio, so it ends a stream by
/// cancelling the listen request.
#[derive(Default)]
pub(crate) struct OpenListens(std::collections::HashMap<String, tokio::task::AbortHandle>);

impl OpenListens {
    /// End the stream the listen request `id` opened. Aborting its task
    /// drops the stream, which releases what it holds.
    fn end(&mut self, id: &Value) {
        if let Some(stream) = self.0.remove(&id.to_string()) {
            stream.abort();
        }
    }

    /// Whether a stream the listen request `id` opened is still open.
    fn is_open(&mut self, id: &Value) -> bool {
        self.0.retain(|_, stream| !stream.is_finished());
        self.0.contains_key(&id.to_string())
    }

    fn insert(&mut self, id: &Value, stream: tokio::task::AbortHandle) {
        self.0.insert(id.to_string(), stream);
    }
}

/// Run the stdio transport. Reads from stdin, writes to stdout. Returns when
/// stdin closes or the gateway shuts down.
pub async fn serve(state: AppState, mut shutdown: tokio::sync::watch::Receiver<()>) -> Result<()> {
    let mut lines = spawn_stdin_reader();
    let mut writer = tokio::io::stdout();
    let (frames_tx, mut frames_rx) = mpsc::channel::<Value>(LISTEN_FRAME_BUFFER);
    let mut listens = OpenListens::default();
    let session_id = open_process_session(&state);

    info!("stdio transport ready, reading from stdin");

    loop {
        enum StdioEvent {
            StdinLine(Option<std::io::Result<String>>),
            Shutdown,
            Frame(Value),
        }

        let event = tokio::select! {
            next = lines.recv() => StdioEvent::StdinLine(next),
            _ = shutdown.changed() => StdioEvent::Shutdown,
            Some(frame) = frames_rx.recv() => StdioEvent::Frame(frame),
        };

        let line = match event {
            StdioEvent::Shutdown => {
                info!("stdio transport received shutdown signal");
                break;
            }
            StdioEvent::Frame(frame) => {
                write_json_line(&mut writer, &frame).await?;
                continue;
            }
            StdioEvent::StdinLine(Some(Ok(line))) => line,
            StdioEvent::StdinLine(Some(Err(e))) => {
                error!(error = %e, "stdin read error");
                break;
            }
            StdioEvent::StdinLine(None) => {
                info!("stdin closed (EOF)");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        debug!(line = %trimmed, "received message from stdin");

        let body: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let error = ProtocolError::parse_error(format!("parse error: {e}"));
                write_json_line(&mut writer, &error_line(error)).await?;
                continue;
            }
        };

        handle_message(
            &state,
            &session_id,
            body,
            &frames_tx,
            &mut writer,
            &mut listens,
        )
        .await?;
    }

    state.runtime.load().terminate_session(&session_id);
    info!("stdio transport stopped");
    Ok(())
}

/// Open the session every request of this process runs under. The process is
/// the only client, so the session is its own and no request names another.
pub(crate) fn open_process_session(state: &AppState) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    state
        .runtime
        .load()
        .materialize_ephemeral_session(&session_id);
    session_id
}

/// Dispatch one message and write its answer.
pub(crate) async fn handle_message<W: AsyncWrite + Unpin>(
    state: &AppState,
    session_id: &str,
    body: Value,
    frames: &mpsc::Sender<Value>,
    writer: &mut W,
    listens: &mut OpenListens,
) -> Result<()> {
    // A cancel that names a listen request ends its stream; it still goes
    // to the dispatch, which answers nothing.
    if body.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && let Some(listen_id) = body.pointer("/params/requestId")
    {
        listens.end(listen_id);
    }

    // stdio resolves no identity. Identity plugins (OIDC, JWT,
    // header-asserted, ...) resolve a remote principal from HTTP headers and
    // bearer tokens; over stdio there is no wire credential. The caller is
    // the OS process that owns the fd pair, and authorization is which binary
    // was allowed to spawn MCPG. The process boundary supplies the trust.
    let identity = RequestIdentity::Anonymous {
        source: "stdio".to_owned(),
    };
    let mut ctx = RequestContext::new(
        GatewayRequestId::new(),
        None,
        identity,
        TransportKind::Stdio,
    );
    ctx.session_id = Some(session_id.to_owned());

    let runtime = state.runtime.load_full();
    let config = state.config.load();
    match dispatch(&runtime, &config, body, ctx, None).await {
        DispatchOutcome::Rejected(rejection) => {
            write_json_line(writer, &transport_rejection_body(&rejection)).await
        }
        DispatchOutcome::Stream {
            plan: StreamPlan::SubscriptionsListen,
            ctx,
            session_id,
            body,
        } => {
            let listen_id = body.get("id").cloned().unwrap_or(Value::Null);
            // The id is how the client ends the stream, so two open streams
            // never share one.
            if listens.is_open(&listen_id) {
                let error = ProtocolError::application(
                    Some(listen_id),
                    crate::protocol::INVALID_REQUEST_CODE,
                    "a subscriptions/listen stream with this id is already open",
                    None,
                );
                return write_json_line(writer, &error_line(error)).await;
            }
            match open_listen(state, &ctx, &session_id, &body).await {
                Ok(listen) => {
                    let stream = tokio::spawn(forward_listen(listen, frames.clone()));
                    listens.insert(&listen_id, stream.abort_handle());
                    Ok(())
                }
                Err(refusal) => {
                    let error = refusal.into_protocol_error(body.get("id").cloned());
                    write_json_line(writer, &error_line(error)).await
                }
            }
        }
        DispatchOutcome::Stream {
            plan: StreamPlan::EventsStream,
            body,
            ..
        } => {
            let error = ProtocolError::method_not_found(
                body.get("id").cloned(),
                StreamPlan::EventsStream.method(),
            );
            write_json_line(writer, &error_line(error)).await
        }
        DispatchOutcome::Response {
            response,
            notifications,
            ..
        } => {
            for notification in &notifications {
                write_json_line(writer, notification).await?;
            }
            match response {
                Ok(response) => write_response(writer, response).await,
                Err(error) => write_json_line(writer, &error_line(error)).await,
            }
        }
    }
}

/// Copy a listen stream's frames to stdout until the stream ends or the
/// transport stops; dropping the stream releases what it holds.
async fn forward_listen(mut listen: ListenStream, frames: mpsc::Sender<Value>) {
    loop {
        let frame = tokio::select! {
            () = frames.closed() => return,
            frame = listen.next() => frame,
        };
        let Some(frame) = frame else {
            return;
        };
        if frames.send(frame).await.is_err() {
            return;
        }
    }
}

/// Write the runtime's answer. A notification has none.
async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: ProtocolHttpResponse,
) -> Result<()> {
    match response.response {
        ProtocolResponse::JsonRpcSuccess(success) => write_json_line(writer, &success).await,
        ProtocolResponse::JsonRpcError(mut error) => {
            crate::transports::http::strip_internal_markers(&mut error);
            write_json_line(writer, &error).await
        }
        ProtocolResponse::NotificationAccepted => {
            debug!("notification accepted (no response)");
            Ok(())
        }
    }
}

/// The JSON-RPC error line of `error`.
fn error_line(error: ProtocolError) -> Value {
    serde_json::to_value(error.into_jsonrpc_error()).unwrap_or_default()
}

/// Read stdin line by line on a dedicated OS thread. A read on tokio's
/// blocking pool cannot be cancelled, so it keeps the runtime from shutting
/// down while the client holds stdin open; this thread ends with the process.
fn spawn_stdin_reader() -> mpsc::Receiver<std::io::Result<String>> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::Builder::new()
        .name("mcpg-stdin".to_owned())
        .spawn(move || {
            use std::io::BufRead;
            let mut stdin = std::io::stdin().lock();
            loop {
                let mut line = String::new();
                match stdin.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if tx.blocking_send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
        })
        .expect("spawn the stdin reader thread");
    rx
}

async fn write_json_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &impl serde::Serialize,
) -> Result<()> {
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

    #[test]
    fn an_error_line_is_a_jsonrpc_error_with_the_request_id() {
        let line = error_line(ProtocolError::method_not_found(
            Some(serde_json::json!(4)),
            "events/stream",
        ));
        assert_eq!(line["jsonrpc"], "2.0");
        assert_eq!(line["id"], 4);
        assert_eq!(
            line["error"]["code"],
            crate::protocol::METHOD_NOT_FOUND_CODE
        );
    }

    #[test]
    fn a_parse_error_line_has_a_null_id() {
        let line = error_line(ProtocolError::parse_error("parse error: eof"));
        assert!(line["id"].is_null());
        assert_eq!(line["error"]["code"], crate::protocol::PARSE_ERROR_CODE);
    }
}
