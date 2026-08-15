use super::*;

impl GatewayRuntime {
    /// Return summary descriptions of all configured bindings for the admin API.
    pub fn binding_summaries(&self) -> Vec<crate::admin::service::BackendSummary> {
        self.capability_registry
            .tools()
            .iter()
            .map(|t| crate::admin::service::BackendSummary {
                name: t.name.clone(),
                title: t.title.clone(),
                backend: "tool".to_owned(),
                has_retry: false,
                has_payment: false,
            })
            .collect()
    }

    /// Return summary descriptions of every registered plugin for
    /// the admin API (tool gates, transforms, identity providers,
    /// bindings, and watch strategies — not just tool gates).
    pub fn plugin_summaries(&self) -> Vec<crate::admin::service::PluginSummary> {
        self.plugin_registry
            .loaded_plugins()
            .into_iter()
            .map(|info| crate::admin::service::PluginSummary {
                id: info.id,
                name: info.name,
                version: info.version,
                class: info.plugin_class,
                tier: info.tier,
                protocol_version: info.protocol_version,
                state: info.state,
            })
            .collect()
    }

    /// Returns sorted name sets for tools, prompts, and resources (including templates).
    /// Used by hot-reload diffing to detect inventory changes.
    pub fn inventory_names(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut tools: Vec<String> = self
            .capability_registry
            .tools()
            .iter()
            .map(|t| t.name.clone())
            .collect();
        let mut prompts: Vec<String> = self
            .capability_registry
            .prompts()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let mut resources: Vec<String> = self
            .capability_registry
            .resources()
            .iter()
            .map(|r| r.name.clone())
            .collect();
        for t in self.capability_registry.resource_templates() {
            resources.push(format!("template:{}", t.name));
        }
        tools.sort();
        prompts.sort();
        resources.sort();
        (tools, prompts, resources)
    }

    pub fn readiness_snapshot(&self) -> ReadinessSnapshot {
        let mut checks = vec![
            ReadinessCheck {
                name: "config_valid".to_owned(),
                status: ReadinessStatus::Ready,
                detail: "application config loaded and validated".to_owned(),
            },
            ReadinessCheck {
                name: "runtime_initialized".to_owned(),
                status: ReadinessStatus::Ready,
                detail: "gateway runtime state initialized".to_owned(),
            },
            ReadinessCheck {
                name: "logging_initialized".to_owned(),
                status: if self.logging_initialized {
                    ReadinessStatus::Ready
                } else {
                    ReadinessStatus::NotReady
                },
                detail: if self.logging_initialized {
                    "structured logging initialized".to_owned()
                } else {
                    "structured logging not initialized".to_owned()
                },
            },
            ReadinessCheck {
                name: "http_transport_configured".to_owned(),
                status: if self.server_bind_address.trim().is_empty()
                    || !self.health_path.starts_with('/')
                {
                    ReadinessStatus::NotReady
                } else {
                    ReadinessStatus::Ready
                },
                detail: format!(
                    "bind_address={}, health_path={}",
                    self.server_bind_address, self.health_path
                ),
            },
        ];

        // NATS readiness: the binding plugin owns its own client; the host
        // no longer observes NATS connection state directly. Plugins can
        // expose health via their own manifest / shutdown hooks in future.

        // Overall status is computed from the base checks; the cluster
        // coordinator check only affects it under the `fail` gate.
        let mut status = if checks
            .iter()
            .all(|check| matches!(check.status, ReadinessStatus::Ready))
        {
            ReadinessStatus::Ready
        } else {
            ReadinessStatus::NotReady
        };

        // Coordinator health gate. Read the operator's
        // `cluster.readiness_gate` from the live config snapshot; the
        // periodic probe maintains `CLUSTER_BACKEND_UP`.
        if let Some(gate) = self
            .shared_services
            .load()
            .as_ref()
            .map(|s| s.config_snapshot.cluster.readiness_gate)
            && !matches!(gate, crate::config::ClusterReadinessGate::Off)
        {
            let up = CLUSTER_BACKEND_UP.load(std::sync::atomic::Ordering::Relaxed);
            // Only surface a check once the backend has actually been
            // probed (`up != NOT_PROBED`) — a KV-less coordinator
            // (consul/etcd) or pre-first-probe window stays silent.
            if up != CLUSTER_UP_NOT_PROBED {
                let healthy = up == CLUSTER_UP_HEALTHY;
                let fail_gate = matches!(gate, crate::config::ClusterReadinessGate::Fail);
                checks.push(ReadinessCheck {
                    name: "cluster_backend".to_owned(),
                    status: if healthy {
                        ReadinessStatus::Ready
                    } else {
                        ReadinessStatus::NotReady
                    },
                    detail: if healthy {
                        "cluster coordinator reachable (KV ping ok)".to_owned()
                    } else if fail_gate {
                        "cluster coordinator UNREACHABLE — /ready fail-closed \
                         (cluster.readiness_gate=fail)"
                            .to_owned()
                    } else {
                        "cluster coordinator UNREACHABLE — degraded \
                         (cluster.readiness_gate=degrade; /ready stays green)"
                            .to_owned()
                    },
                });
                // `fail` flips the overall status; `degrade` is informational.
                if fail_gate && !healthy {
                    status = ReadinessStatus::NotReady;
                }
            }
        }

        ReadinessSnapshot { status, checks }
    }

    /// Spawn the periodic coordinator-health probe. Pings the
    /// coordinator's KV with a fallible `get` of a sentinel key every
    /// `interval` and mirrors reachability to the `mcpg_cluster_backend_up`
    /// gauge (1/0) + the `CLUSTER_BACKEND_UP` cell that
    /// [`Self::readiness_snapshot`]'s gate reads — independent of whether
    /// any lease consumer (cedar / workload) is active. The caller only
    /// spawns this for a clustered coordinator that exposes a KV accessor
    /// (single_node / consul / etcd are skipped — see `run`).
    pub(crate) fn spawn_cluster_health_probe(
        kv: Arc<dyn mcpg_cluster_api::KeyValueStore>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        use std::sync::atomic::Ordering;
        const PROBE_KEY: &str = "mcpg:cluster:health-probe";
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                // A hit OR a clean miss both mean "coordinator answered";
                // only a transport/backend error means "unreachable".
                let up = kv.get(PROBE_KEY).await.is_ok();
                CLUSTER_BACKEND_UP.store(
                    if up {
                        CLUSTER_UP_HEALTHY
                    } else {
                        CLUSTER_UP_DOWN
                    },
                    Ordering::Relaxed,
                );
                metrics::gauge!("mcpg_cluster_backend_up").set(if up { 1.0 } else { 0.0 });
                if !up {
                    warn!(
                        "cluster coordinator health probe failed (KV ping errored) — \
                         mcpg_cluster_backend_up=0"
                    );
                }
            }
        })
    }

    pub fn runtime_snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            service: self.service_name.clone(),
            version: self.service_version.clone(),
            started_at: self.started_at,
            uptime_secs: self.uptime_secs(),
            bind_address: self.server_bind_address.clone(),
            health_path: self.health_path.clone(),
            mcp_path: self.mcp_path.clone(),
            logging: LoggingSnapshot {
                level: self.log_level.clone(),
                sinks: self.log_sinks.iter().map(|s| s.kind.clone()).collect(),
                initialized: self.logging_initialized,
            },
            readiness: self.readiness_snapshot(),
            plugins: PluginSnapshot {
                total_count: self.plugin_registry.total_count(),
                loaded: self.plugin_registry.loaded_plugins(),
            },
        }
    }

    pub fn record_request_received(&self, request_context: &RequestContext, operation: &str) {
        if !self.access_log {
            return;
        }
        info!(
            request_id = %request_context.request_id,
            upstream_request_id = request_context.upstream_request_id.as_deref().unwrap_or(""),
            identity_kind = request_context.identity.label(),
            identity_trust = ?request_context.identity.trust_level(),
            transport = ?request_context.transport,
            operation,
            "request received"
        );
    }

    pub fn record_request_completed(&self, request_context: &RequestContext, operation: &str) {
        if !self.access_log {
            return;
        }
        info!(
            request_id = %request_context.request_id,
            upstream_request_id = request_context.upstream_request_id.as_deref().unwrap_or(""),
            identity_kind = request_context.identity.label(),
            identity_trust = ?request_context.identity.trust_level(),
            transport = ?request_context.transport,
            operation,
            "request completed"
        );
    }
}
