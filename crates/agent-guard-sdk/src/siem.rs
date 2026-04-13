use agent_guard_core::{AuditConfig, AuditRecord};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Shared runtime for SIEM exports to avoid overhead of creating new ones per call.
static SIEM_RUNTIME: OnceLock<Mutex<Option<tokio::runtime::Runtime>>> = OnceLock::new();

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);
const WEBHOOK_RETRY_DELAY: Duration = Duration::from_millis(100);
const WEBHOOK_MAX_ATTEMPTS: usize = 2;

fn with_siem_runtime(f: impl FnOnce(&tokio::runtime::Runtime)) -> bool {
    let runtime_cell = SIEM_RUNTIME.get_or_init(|| Mutex::new(None));
    let mut guard = match runtime_cell.lock() {
        Ok(guard) => guard,
        Err(_) => {
            tracing::error!("Failed to acquire SIEM runtime lock");
            return false;
        }
    };

    if guard.is_none() {
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agent-guard-siem")
            .build()
        {
            Ok(rt) => *guard = Some(rt),
            Err(e) => {
                tracing::error!("Failed to create SIEM runtime: {}", e);
                return false;
            }
        }
    }

    if let Some(rt) = guard.as_ref() {
        f(rt);
        true
    } else {
        false
    }
}

async fn send_webhook(client: reqwest::Client, url: String, record: AuditRecord) {
    for attempt in 1..=WEBHOOK_MAX_ATTEMPTS {
        match client.post(&url).json(&record).send().await {
            Ok(res) if res.status().is_success() => return,
            Ok(res) => {
                tracing::error!(
                    attempt,
                    max_attempts = WEBHOOK_MAX_ATTEMPTS,
                    status = %res.status(),
                    "SIEM webhook failed"
                );
            }
            Err(e) => {
                tracing::error!(
                    attempt,
                    max_attempts = WEBHOOK_MAX_ATTEMPTS,
                    error = %e,
                    "SIEM webhook request failed"
                );
            }
        }

        if attempt < WEBHOOK_MAX_ATTEMPTS {
            tokio::time::sleep(WEBHOOK_RETRY_DELAY).await;
        }
    }
}

/// Dispatches audit events to external SIEM systems.
pub struct SiemExporter {
    config: AuditConfig,
    client: Option<reqwest::Client>,
}

impl SiemExporter {
    pub fn new(config: AuditConfig) -> Self {
        let client = if config.webhook_url.is_some() {
            match reqwest::Client::builder().timeout(WEBHOOK_TIMEOUT).build() {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!("Failed to create SIEM webhook client: {}", e);
                    None
                }
            }
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
            if !with_siem_runtime(|rt| {
                rt.spawn(async move {
                    send_webhook(client, url, record).await;
                });
            }) {
                tracing::error!("SIEM export dropped because no async runtime is available");
            }
        }

        // OTLP Export (Planned)
        if let Some(_endpoint) = &self.config.otlp_endpoint {
            tracing::debug!("OTLP export triggered (implementation pending)");
        }
    }
}
