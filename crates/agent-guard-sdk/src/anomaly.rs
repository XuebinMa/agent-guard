use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    pub max_calls_per_minute: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            max_calls_per_minute: 30,
        }
    }
}

pub struct AnomalyDetector {
    config: AnomalyConfig,
    history: Mutex<HashMap<String, Vec<Instant>>>,
}

impl AnomalyDetector {
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            history: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a tool call is anomalous based on frequency.
    pub fn check(&self, actor: &str) -> bool {
        let mut history = self.history.lock().unwrap();
        let now = Instant::now();
        let minute_ago = now - Duration::from_secs(60);

        let calls = history.entry(actor.to_string()).or_insert_with(Vec::new());
        
        // Cleanup old calls
        calls.retain(|&t| t > minute_ago);
        
        // Add current call
        calls.push(now);

        if calls.len() > self.config.max_calls_per_minute {
            tracing::warn!(
                actor = actor,
                call_count = calls.len(),
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
        Arc::new(AnomalyDetector::new(AnomalyConfig::default()))
    }).clone()
}
