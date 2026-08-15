use super::*;

#[derive(Debug)]
pub(super) struct CommandExecutionResult {
    pub(super) exit_code: Option<i32>,
    pub(super) success: bool,
    pub(super) timed_out: bool,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
    pub(super) read_error: Option<String>,
    pub(super) duration_ms: u128,
}

pub(super) fn execute_command_with_limits(
    config: &CommandToolRuntimeConfig,
    trace_context: Option<&crate::transports::TraceContext>,
) -> Result<CommandExecutionResult, std::io::Error> {
    execute_command_with_optional_input(config, None, trace_context)
}

pub(super) fn execute_command_with_optional_input(
    config: &CommandToolRuntimeConfig,
    stdin_input: Option<&[u8]>,
    trace_context: Option<&crate::transports::TraceContext>,
) -> Result<CommandExecutionResult, std::io::Error> {
    let started_at = Instant::now();
    let mut command = Command::new(&config.command);
    command
        .args(&config.args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // propagate the W3C traceparent into the child process env
    // so tools written as scripts or subprocesses can continue the
    // distributed trace (the env var name matches the OpenTelemetry
    // `OTEL_TRACE_PARENT_ENV` conventions used by most SDK shims).
    if let Some(tp) = trace_context {
        command.env("TRACEPARENT", tp.child_traceparent());
        if let Some(ref ts) = tp.tracestate {
            command.env("TRACESTATE", ts);
        }
    }
    if stdin_input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;

    if let Some(stdin_input) = stdin_input
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(stdin_input)?;
    }

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let stdout_handle = spawn_limited_reader(stdout, config.max_output_bytes);
    let stderr_handle = spawn_limited_reader(stderr, config.max_output_bytes);

    let timeout = Duration::from_millis(config.timeout_ms);
    let mut timed_out = false;
    let exit_status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started_at.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout_result = stdout_handle.join().expect("stdout reader joined");
    let stderr_result = stderr_handle.join().expect("stderr reader joined");
    let read_error = stdout_result.error.or(stderr_result.error);

    Ok(CommandExecutionResult {
        exit_code: exit_status.code(),
        success: exit_status.success() && !timed_out,
        timed_out,
        stdout: String::from_utf8_lossy(&stdout_result.bytes).to_string(),
        stderr: String::from_utf8_lossy(&stderr_result.bytes).to_string(),
        stdout_truncated: stdout_result.truncated,
        stderr_truncated: stderr_result.truncated,
        read_error,
        duration_ms: started_at.elapsed().as_millis(),
    })
}

#[derive(Debug)]
pub(super) struct LimitedReadResult {
    bytes: Vec<u8>,
    truncated: bool,
    error: Option<String>,
}

pub(super) fn spawn_limited_reader<R: Read + Send + 'static>(
    mut reader: R,
    limit: usize,
) -> thread::JoinHandle<LimitedReadResult> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        let mut truncated = false;

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if bytes.len() < limit {
                        let remaining = limit - bytes.len();
                        let copy_len = remaining.min(count);
                        bytes.extend_from_slice(&buffer[..copy_len]);
                        if count > copy_len {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                    }
                }
                Err(error) => {
                    return LimitedReadResult {
                        bytes,
                        truncated,
                        error: Some(error.to_string()),
                    };
                }
            }
        }

        LimitedReadResult {
            bytes,
            truncated,
            error: None,
        }
    })
}
