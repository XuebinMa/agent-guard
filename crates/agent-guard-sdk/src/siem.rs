use agent_guard_core::{AuditConfig, AuditRecord};
use std::sync::OnceLock;

/// Shared runtime for SIEM exports to avoid overhead of creating new ones per call.
static SIEM_RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();

fn get_siem_runtime() -> Option<&'static tokio::runtime::Runtime> {
    SIEM_RUNTIME.get_or_init(|| {
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agent-guard-siem")
            .build() {
                Ok(rt) => Some(rt),
                Err(e) => {
                    tracing::error!("Failed to create SIEM runtime: {}", e);
                    None
                }
            }
    }).as_ref()
}

/// Dispatches audit events to external SIEM systems.
pub struct SiemExporter {
    config: AuditConfig,
    client: Option<reqwest::Client>,
}

impl SiemExporter {
    pub fn new(config: AuditConfig) -> Self {
        let client = if config.webhook_url.is_some() {
            Some(reqwest::Client::new())
        } else {
            None
        };

        Self { config, client }
    }

    /// Asynchronously exports an audit record.
    pub fn export(&self, record: AuditRecord) {
        if !self.config.enabled {
            return;
        }

        // Webhook Export
        if let (Some(url), Some(client)) = (&self.config.webhook_url, &self.client) {
            let url = url.clone();
            let client = client.clone();
            let record = record.clone();
            
            // Dispatch to the shared SIEM runtime
            if let Some(rt) = get_siem_runtime() {
                rt.spawn(async move {
                    match client.post(&url)
                        .json(&record)
                        .send()
                        .await {
                            Ok(res) => {
                                if !res.status().is_success() {
                                    tracing::error!("SIEM Webhook failed with status: {}", res.status());
                                }
                            }
                            Err(e) => {
                                tracing::error!("SIEM Webhook request failed: {}", e);
                            }
                        }
                });
            }
        }

        // OTLP Export (Planned)
        if let Some(_endpoint) = &self.config.otlp_endpoint {
            tracing::debug!("OTLP export triggered (implementation pending)");
        }
    }
}
