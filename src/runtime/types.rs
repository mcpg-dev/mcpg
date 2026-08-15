use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSnapshot {
    pub service: String,
    pub version: String,
    pub started_at: DateTime<Utc>,
    pub uptime_secs: i64,
    pub bind_address: String,
    pub health_path: String,
    pub mcp_path: String,
    pub logging: LoggingSnapshot,
    pub readiness: ReadinessSnapshot,
    pub plugins: PluginSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginSnapshot {
    pub total_count: usize,
    pub loaded: Vec<mcpg_plugin_host::LoadedPluginInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoggingSnapshot {
    pub level: String,
    /// Sink KINDS only. `/runtime` is served without authentication, and a
    /// `SinkConfig` carries the sink's own settings — collector endpoints,
    /// file paths, and whatever headers an OTLP sink was given. Those are
    /// operator configuration, not a liveness signal.
    pub sinks: Vec<String>,
    pub initialized: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessSnapshot {
    pub status: ReadinessStatus,
    pub checks: Vec<ReadinessCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub status: ReadinessStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    NotReady,
}
