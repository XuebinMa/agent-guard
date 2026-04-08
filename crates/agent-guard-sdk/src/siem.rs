use agent_guard_core::{AuditConfig, AuditRecord};
use std::sync::OnceLock;

/// Shared runtime for SIEM exports to avoid overhead of creating new ones per call.
static SIEM_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn get_siem_runtime() -> &'static tokio::runtime::Runtime {
    SIEM_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agent-guard-siem")
            .build()
            .expect("Failed to create SIEM runtime")
    })
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
            let rt = get_siem_runtime();
            rt.spawn(async move {
                let _ = client.post(&url)
                    .json(&record)
                    .send()
                    .await;
            });
        }

        // OTLP Export (Planned)
        if let Some(_endpoint) = &self.config.otlp_endpoint {
            tracing::debug!("OTLP export triggered (implementation pending)");
        }
    }
}
