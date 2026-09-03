//! Rate limiting and the deny fuse.
//!
//! ## Two clocks, on purpose
//!
//! Every observation is recorded on both a monotonic and a wall clock, and
//! the two are not interchangeable:
//!
//! - **Decisions** compare monotonic `Instant`s. A system clock that steps
//!   backwards — an NTP correction, or a host an attacker can influence —
//!   must not be able to age observations out of a window and unlock an
//!   actor.
//! - **Evidence** is emitted as wall-clock `DateTime<Utc>`. An `Instant` is
//!   not serialisable and is meaningless in another process, so a verdict
//!   recorded with monotonic times could never be re-checked by a reader.
//!
//! Recording only one of them loses either the security property or the
//! ability to audit; this module keeps them paired and never derives one from
//! the other.
//!
//! ## What a verdict carries
//!
//! A verdict is an authority claim, so it travels with the observations it
//! was derived from ([`AnomalyEvidence`]). A reader holding the emitted
//! record can recompute it: the witnesses lie inside the stated window and
//! reach the stated threshold. Without that, an `AgentLocked` record asserts
//! a lock and offers nothing to check it against.

use agent_guard_core::{AnomalyConfig, AnomalyEvidence, AnomalyRule};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One observation, on both clocks. See the module note on why both.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    at: Instant,
    wall: DateTime<Utc>,
}

impl Observation {
    fn now() -> Self {
        Self {
            at: Instant::now(),
            wall: Utc::now(),
        }
    }
}

pub struct ActorState {
    pub call_history: Vec<Observation>,
    pub denial_history: Vec<Observation>,
    /// Set when the history cap dropped older entries, so the counts derived
    /// from these vectors are lower bounds rather than exact.
    pub calls_truncated: bool,
    pub denials_truncated: bool,
    pub is_locked: bool,
    /// The evidence as it stood when the fuse tripped.
    ///
    /// A lock outlives the window that caused it, so re-deriving the witness
    /// set on a later check would report whatever survived pruning rather
    /// than what actually justified the lock. It is captured once, at the
    /// moment of the decision, and replayed unchanged afterwards.
    pub lock_evidence: Option<AnomalyEvidence>,
    pub last_seen: Instant,
}

impl Default for ActorState {
    fn default() -> Self {
        Self {
            call_history: Vec::new(),
            denial_history: Vec::new(),
            calls_truncated: false,
            denials_truncated: false,
            is_locked: false,
            lock_evidence: None,
            last_seen: Instant::now(),
        }
    }
}

pub struct AnomalyDetector {
    states: Mutex<HashMap<String, ActorState>>,
}

const MAX_TRACKED_SUBJECTS: usize = 4096;
const STALE_SUBJECT_TTL: Duration = Duration::from_secs(60 * 60);
/// CWE-770: bound the per-actor history so a flood cannot exhaust memory.
const HISTORY_CAP: usize = 1000;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AnomalyStatus {
    Normal,
    RateLimited,
    Locked,
}

/// A verdict and the material to re-check it.
///
/// `evidence` is `None` only where there is genuinely nothing to show: a
/// `Normal` verdict decides nothing, and a fail-closed lock taken because the
/// state mutex was poisoned rests on no observations at all. A reader must
/// treat a decided verdict with no evidence as unverifiable rather than
/// assume it was justified.
#[derive(Debug, Clone)]
pub struct AnomalyVerdict {
    pub status: AnomalyStatus,
    pub evidence: Option<AnomalyEvidence>,
}

impl AnomalyVerdict {
    fn normal() -> Self {
        Self {
            status: AnomalyStatus::Normal,
            evidence: None,
        }
    }

    fn decided(status: AnomalyStatus, evidence: Option<AnomalyEvidence>) -> Self {
        Self { status, evidence }
    }
}

/// Build the evidence for a verdict from the observations that produced it.
fn evidence_from(
    rule: AnomalyRule,
    window_seconds: u64,
    threshold: usize,
    history: &[Observation],
    truncated: bool,
) -> AnomalyEvidence {
    AnomalyEvidence {
        rule,
        window_seconds,
        threshold,
        observed: history.len(),
        witnesses: history.iter().map(|observation| observation.wall).collect(),
        truncated,
    }
}

/// Drop the oldest entry when the cap is reached, reporting whether anything
/// was lost so the resulting count is not silently presented as exact.
fn cap_history(history: &mut Vec<Observation>, truncated: &mut bool) {
    while history.len() > HISTORY_CAP {
        history.remove(0);
        *truncated = true;
    }
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

    /// Check whether a call is anomalous, or the actor is already locked.
    pub fn check(&self, actor: &str, config: &AnomalyConfig) -> AnomalyVerdict {
        if !config.enabled {
            return AnomalyVerdict::normal();
        }

        let observation = Observation::now();
        let now = observation.at;
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Fail closed. This lock rests on no observations, so it
                // carries no evidence and must read as unverifiable.
                tracing::error!(
                    actor = actor,
                    "AnomalyDetector state mutex poisoned in check; failing closed to Locked"
                );
                return AnomalyVerdict::decided(AnomalyStatus::Locked, None);
            }
        };
        compact_states(&mut states, config, now);
        let state = states.entry(actor.to_string()).or_default();
        state.last_seen = now;

        if state.is_locked {
            return AnomalyVerdict::decided(AnomalyStatus::Locked, state.lock_evidence.clone());
        }

        // 1. Rate limit.
        let call_window = Duration::from_secs(config.rate_limit.window_seconds);
        let call_cutoff = now - call_window;
        state.call_history.retain(|o| o.at > call_cutoff);
        state.call_history.push(observation);
        cap_history(&mut state.call_history, &mut state.calls_truncated);

        if state.call_history.len() > config.rate_limit.max_calls {
            tracing::warn!(
                actor = actor,
                call_count = state.call_history.len(),
                window_seconds = config.rate_limit.window_seconds,
                max_calls = config.rate_limit.max_calls,
                "Anomaly detected: high tool call frequency"
            );
            let evidence = evidence_from(
                AnomalyRule::RateLimit,
                config.rate_limit.window_seconds,
                config.rate_limit.max_calls,
                &state.call_history,
                state.calls_truncated,
            );
            return AnomalyVerdict::decided(AnomalyStatus::RateLimited, Some(evidence));
        }

        // 2. Deny fuse, in case it was armed by denials reported since the
        //    last check.
        if config.deny_fuse.enabled {
            let fuse_window = Duration::from_secs(config.deny_fuse.window_seconds);
            let fuse_cutoff = now - fuse_window;
            state.denial_history.retain(|o| o.at > fuse_cutoff);

            if state.denial_history.len() >= config.deny_fuse.threshold {
                tracing::error!(
                    actor = actor,
                    denial_count = state.denial_history.len(),
                    threshold = config.deny_fuse.threshold,
                    "Anomaly detected: agent locked due to too many denials (Deny Fuse)"
                );
                let evidence = evidence_from(
                    AnomalyRule::DenyFuse,
                    config.deny_fuse.window_seconds,
                    config.deny_fuse.threshold,
                    &state.denial_history,
                    state.denials_truncated,
                );
                state.is_locked = true;
                state.lock_evidence = Some(evidence.clone());
                return AnomalyVerdict::decided(AnomalyStatus::Locked, Some(evidence));
            }
        }

        AnomalyVerdict::normal()
    }

    /// Report a denial for an actor, which may trip the deny fuse.
    pub fn report_denial(&self, actor: &str, config: &AnomalyConfig) {
        if !config.enabled || !config.deny_fuse.enabled {
            return;
        }

        let observation = Observation::now();
        let now = observation.at;
        let mut states = match self.states.lock() {
            Ok(guard) => guard,
            // Fail-closed: recover the poisoned guard so the denial is still
            // recorded and the Deny Fuse can still trip. Dropping it here would
            // let an actor exhaust the threshold without ever locking.
            Err(poisoned) => {
                tracing::error!(
                    actor = actor,
                    "AnomalyDetector state mutex poisoned in report_denial; recovering to record denial"
                );
                poisoned.into_inner()
            }
        };
        compact_states(&mut states, config, now);
        let state = states.entry(actor.to_string()).or_default();
        state.last_seen = now;

        if state.is_locked {
            return;
        }

        state.denial_history.push(observation);
        cap_history(&mut state.denial_history, &mut state.denials_truncated);

        let fuse_window = Duration::from_secs(config.deny_fuse.window_seconds);
        let fuse_cutoff = now - fuse_window;
        state.denial_history.retain(|o| o.at > fuse_cutoff);

        if state.denial_history.len() >= config.deny_fuse.threshold {
            tracing::error!(
                actor = actor,
                denial_count = state.denial_history.len(),
                threshold = config.deny_fuse.threshold,
                "Anomaly detected: agent locked due to too many denials (Deny Fuse)"
            );
            // Captured here, at the decision, rather than re-derived on the
            // next check when pruning may already have removed witnesses.
            state.lock_evidence = Some(evidence_from(
                AnomalyRule::DenyFuse,
                config.deny_fuse.window_seconds,
                config.deny_fuse.threshold,
                &state.denial_history,
                state.denials_truncated,
            ));
            state.is_locked = true;
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
            .retain(|o| now.duration_since(o.at) <= call_window);
        state
            .denial_history
            .retain(|o| now.duration_since(o.at) <= fuse_window);

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

        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Normal
        );
        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Normal
        );
        assert_eq!(
            detector.check("actor-1", &config).status,
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
        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Normal
        );

        // 2. Report 3rd denial - now locked
        detector.report_denial("actor-1", &config);
        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Locked
        );

        // 3. Subsequent checks still locked
        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Locked
        );
    }

    /// The lock is justified by the denials that tripped it, and the evidence
    /// keeps saying so on every later check — not just the first one.
    #[test]
    fn lock_evidence_is_captured_at_the_decision_and_replayed() {
        let detector = AnomalyDetector::new();
        let config = AnomalyConfig {
            enabled: true,
            rate_limit: RateLimitConfig::default(),
            deny_fuse: DenyFuseConfig {
                enabled: true,
                threshold: 2,
                window_seconds: 60,
            },
        };

        detector.report_denial("actor-1", &config);
        detector.report_denial("actor-1", &config);

        let first = detector.check("actor-1", &config);
        let evidence = first.evidence.expect("a lock must carry its evidence");
        assert_eq!(evidence.rule, AnomalyRule::DenyFuse);
        assert_eq!(evidence.threshold, 2);
        assert_eq!(evidence.observed, 2);
        assert_eq!(evidence.witnesses.len(), 2);
        assert!(!evidence.truncated);

        let later = detector.check("actor-1", &config);
        assert_eq!(
            later.evidence.as_ref(),
            Some(&evidence),
            "the evidence for a lock must not drift on later checks"
        );
    }

    /// A rate-limit verdict states the observations it counted, so the count
    /// can be checked against the limit it was compared with.
    #[test]
    fn rate_limit_verdict_carries_its_observations() {
        let detector = AnomalyDetector::new();
        let config = AnomalyConfig {
            enabled: true,
            rate_limit: RateLimitConfig {
                window_seconds: 60,
                max_calls: 1,
            },
            deny_fuse: DenyFuseConfig::default(),
        };

        assert_eq!(
            detector.check("actor-1", &config).status,
            AnomalyStatus::Normal
        );
        let verdict = detector.check("actor-1", &config);
        assert_eq!(verdict.status, AnomalyStatus::RateLimited);

        let evidence = verdict.evidence.expect("a rate limit must carry evidence");
        assert_eq!(evidence.rule, AnomalyRule::RateLimit);
        assert_eq!(evidence.threshold, 1);
        assert_eq!(evidence.observed, 2);
        assert_eq!(evidence.witnesses.len(), evidence.observed);
        assert!(
            evidence.observed > evidence.threshold,
            "the recorded count must actually exceed the recorded limit"
        );
    }

    /// A `Normal` verdict decides nothing, so it has nothing to evidence.
    #[test]
    fn normal_verdict_carries_no_evidence() {
        let detector = AnomalyDetector::new();
        let config = AnomalyConfig {
            enabled: true,
            rate_limit: RateLimitConfig {
                window_seconds: 60,
                max_calls: 10,
            },
            deny_fuse: DenyFuseConfig::default(),
        };

        let verdict = detector.check("actor-1", &config);
        assert_eq!(verdict.status, AnomalyStatus::Normal);
        assert!(verdict.evidence.is_none());
    }
}
