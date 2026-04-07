use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use agent_guard_core::AnomalyConfig;

pub struct AnomalyDetector {
    history: Mutex<HashMap<String, Vec<Instant>>>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            history: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a tool call is anomalous based on frequency using the provided config.
    pub fn check(&self, actor: &str, config: &AnomalyConfig) -> bool {
        if !config.enabled {
            return false;
        }

        let mut history = self.history.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(config.rate_limit.window_seconds);
        let cutoff = now - window;

        let calls = history.entry(actor.to_string()).or_insert_with(Vec::new);
        
        // Cleanup old calls
        calls.retain(|&t| t > cutoff);
        
        // Add current call
        calls.push(now);

        if calls.len() > config.rate_limit.max_calls {
            tracing::warn!(
                actor = actor,
                call_count = calls.len(),
                window_seconds = config.rate_limit.window_seconds,
                max_calls = config.rate_limit.max_calls,
                "Anomaly detected: high tool call frequency"
            );
            return true;
        }

        false
    }
}

pub static GLOBAL_DETECTOR: std::sync::OnceLock<Arc<AnomalyDetector>> = std::sync::OnceLock::new();

pub fn get_detector() -> Arc<AnomalyDetector> {
    GLOBAL_DETECTOR.get_or_init(|| {
        Arc::new(AnomalyDetector::new())
    }).clone()
}
