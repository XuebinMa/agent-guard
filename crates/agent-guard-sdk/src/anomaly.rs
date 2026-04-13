use agent_guard_core::AnomalyConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct ActorState {
    pub call_history: Vec<Instant>,
    pub denial_history: Vec<Instant>,
    pub is_locked: bool,
    pub last_seen: Instant,
}

impl Default for ActorState {
    fn default() -> Self {
        Self {
            call_history: Vec::new(),
            denial_history: Vec::new(),
            is_locked: false,
            last_seen: Instant::now(),
        }
    }
}

pub struct AnomalyDetector {
    states: Mutex<HashMap<String, ActorState>>,
}

const MAX_TRACKED_SUBJECTS: usize = 4096;
const STALE_SUBJECT_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, PartialEq, Eq)]
pub enum AnomalyStatus {
    Normal,
    RateLimited,
    Locked,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a tool call is anomalous or if the actor is locked.
    pub fn check(&self, actor: &str, config: &AnomalyConfig) -> AnomalyStatus {
        if !config.enabled {
            return AnomalyStatus::Normal;
        }

        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => {
                // If the mutex is poisoned, we fail-closed for security.
                return AnomalyStatus::Locked;
            }
        };
        compact_states(&mut states, config, now);
        let state = states.entry(actor.to_string()).or_default();
        state.last_seen = now;

        if state.is_locked {
            return AnomalyStatus::Locked;
        }

        // 1. Check Rate Limit
        let call_window = Duration::from_secs(config.rate_limit.window_seconds);
        let call_cutoff = now - call_window;
        state.call_history.retain(|&t| t > call_cutoff);
        state.call_history.push(now);

        // CWE-CWE-770: Allocation of Resources Without Limits or Throttling
        // Limit history to prevent OOM
        if state.call_history.len() > 1000 {
            state.call_history.remove(0);
        }

        if state.call_history.len() > config.rate_limit.max_calls {
            tracing::warn!(
                actor = actor,
                call_count = state.call_history.len(),
                window_seconds = config.rate_limit.window_seconds,
                max_calls = config.rate_limit.max_calls,
                "Anomaly detected: high tool call frequency"
            );
            return AnomalyStatus::RateLimited;
        }

        // 2. Check Deny Fuse (Pre-emptive check - if already met)
        if config.deny_fuse.enabled {
            let fuse_window = Duration::from_secs(config.deny_fuse.window_seconds);
            let fuse_cutoff = now - fuse_window;
            state.denial_history.retain(|&t| t > fuse_cutoff);

            if state.denial_history.len() >= config.deny_fuse.threshold {
                state.is_locked = true;
                tracing::error!(
                    actor = actor,
                    denial_count = state.denial_history.len(),
                    threshold = config.deny_fuse.threshold,
                    "Anomaly detected: agent locked due to too many denials (Deny Fuse)"
                );
                return AnomalyStatus::Locked;
            }
        }

        AnomalyStatus::Normal
    }

    /// Report a denial for an actor to potentially trigger the Deny Fuse.
    pub fn report_denial(&self, actor: &str, config: &AnomalyConfig) {
        if !config.enabled || !config.deny_fuse.enabled {
            return;
        }

        let now = Instant::now();
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => return, // Silent return on poison for non-critical update
        };
        compact_states(&mut states, config, now);
        let state = states.entry(actor.to_string()).or_default();
        state.last_seen = now;

        if state.is_locked {
            return;
        }

        state.denial_history.push(now);

        // Limit history to prevent OOM
        if state.denial_history.len() > 1000 {
            state.denial_history.remove(0);
        }

        let fuse_window = Duration::from_secs(config.deny_fuse.window_seconds);
        let fuse_cutoff = now - fuse_window;
        state.denial_history.retain(|&t| t > fuse_cutoff);

        if state.denial_history.len() >= config.deny_fuse.threshold {
            state.is_locked = true;
            tracing::error!(
                actor = actor,
                denial_count = state.denial_history.len(),
                threshold = config.deny_fuse.threshold,
                "Anomaly detected: agent locked due to too many denials (Deny Fuse)"
            );
        }
    }
}

fn compact_states(states: &mut HashMap<String, ActorState>, config: &AnomalyConfig, now: Instant) {
    let call_window = Duration::from_secs(config.rate_limit.window_seconds);
    let fuse_window = Duration::from_secs(config.deny_fuse.window_seconds);
    let retention = call_window.max(fuse_window).max(STALE_SUBJECT_TTL);

    states.retain(|_, state| {
        state
            .call_history
            .retain(|&t| now.duration_since(t) <= call_window);
        state
            .denial_history
            .retain(|&t| now.duration_since(t) <= fuse_window);

        let recently_seen = now.duration_since(state.last_seen) <= retention;
        let has_recent_activity =
            !state.call_history.is_empty() || !state.denial_history.is_empty();

        recently_seen || has_recent_activity || state.is_locked
    });

    while states.len() > MAX_TRACKED_SUBJECTS {
        let Some(oldest_key) = states
            .iter()
            .min_by_key(|(_, state)| state.last_seen)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        states.remove(&oldest_key);
    }
}

pub static GLOBAL_DETECTOR: std::sync::OnceLock<Arc<AnomalyDetector>> = std::sync::OnceLock::new();

pub fn get_detector() -> Arc<AnomalyDetector> {
    GLOBAL_DETECTOR
        .get_or_init(|| Arc::new(AnomalyDetector::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_core::{AnomalyConfig, DenyFuseConfig, RateLimitConfig};

    #[test]
    fn test_rate_limiting() {
        let detector = AnomalyDetector::new();
        let config = AnomalyConfig {
            enabled: true,
            rate_limit: RateLimitConfig {
                window_seconds: 60,
                max_calls: 2,
            },
            deny_fuse: DenyFuseConfig::default(),
        };

        assert_eq!(detector.check("actor-1", &config), AnomalyStatus::Normal);
        assert_eq!(detector.check("actor-1", &config), AnomalyStatus::Normal);
        assert_eq!(
            detector.check("actor-1", &config),
            AnomalyStatus::RateLimited
        );
    }

    #[test]
    fn test_deny_fuse() {
        let detector = AnomalyDetector::new();
        let config = AnomalyConfig {
            enabled: true,
            rate_limit: RateLimitConfig::default(),
            deny_fuse: DenyFuseConfig {
                enabled: true,
                threshold: 3,
                window_seconds: 60,
            },
        };

        // 1. Report 2 denials - not locked yet
        detector.report_denial("actor-1", &config);
        detector.report_denial("actor-1", &config);
        assert_eq!(detector.check("actor-1", &config), AnomalyStatus::Normal);

        // 2. Report 3rd denial - now locked
        detector.report_denial("actor-1", &config);
        assert_eq!(detector.check("actor-1", &config), AnomalyStatus::Locked);

        // 3. Subsequent checks still locked
        assert_eq!(detector.check("actor-1", &config), AnomalyStatus::Locked);
    }
}
