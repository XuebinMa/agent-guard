use agent_guard_core::{AuditConfig, AuditRecord};

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

        // 1. Local logging (already handled by write_audit in guard.rs, 
        // but we could extend it here for unified SIEM logic).

        // 2. Webhook Export
        if let (Some(url), Some(client)) = (&self.config.webhook_url, &self.client) {
            let url = url.clone();
            let client = client.clone();
            let record = record.clone();
            
            // Fire and forget for now to avoid blocking the main thread
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                
                runtime.block_on(async {
                    let _ = client.post(&url)
                        .json(&record)
                        .send()
                        .await;
                });
            });
        }

        // 3. OTLP Export (Planned)
        if let Some(_endpoint) = &self.config.otlp_endpoint {
            // OTLP implementation using opentelemetry-otlp crate would go here.
            // For now, we'll log that it's planned.
            tracing::debug!("OTLP export triggered (implementation pending)");
        }
    }
}
