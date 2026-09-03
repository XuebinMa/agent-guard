use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    payload::{extract_bash_command as extract_core_bash_command, ExtractedPayload},
    AuditConfig, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine, RuntimeDecision,
    Tool,
};
use agent_guard_sandbox::Sandbox;
use agent_guard_validators::bash::{
    canonical_policy_subjects, git_push_intents, validate_bash_command, GitPushIntent,
    ValidationResult,
};
use agent_guard_validators::http::validate_http_request;
use arc_swap::ArcSwap;
use thiserror::Error;
use uuid::Uuid;

use crate::audit_writer::AuditFileWriter;
use crate::guard_audit::{stdout_audit_sink, AuditSink};
use crate::guard_git_preview::with_git_push_preview;
use crate::guard_helpers::{
    anomaly_subject, classify_block_reason, policy_mode_to_permission_mode,
    runtime_decision_for_input,
};
use crate::policy_signing::PolicyVerification;
use crate::sandbox_resolution::{resolve_default_sandbox, resolve_sandbox_by_name};
pub use crate::sandbox_resolution::{DefaultSandboxDiagnosis, UnknownBackendError};
use crate::siem::SiemExporter;

// The execute/run result types live in the sibling `enforce` and `runtime`
// modules; re-export them here so `agent_guard_sdk::guard::*` exposes the full
// decision surface from one path.
pub use crate::enforce::{ExecuteOutcome, ExecuteResult};
pub use crate::runtime::{HandoffResult, RuntimeOutcome, RuntimeResult};

// ── GuardInitError ────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum GuardInitError {
    #[error("policy error: {0}")]
    Policy(#[from] agent_guard_core::PolicyError),
    #[error("failed to open audit file '{path}': {source}")]
    AuditFileOpen {
        path: String,
        source: std::io::Error,
    },
    #[error("signing key load error: {0}")]
    SigningKeyLoad(String),
}

// ── Guard ─────────────────────────────────────────────────────────────────────

/// Main entry point for the agent-guard SDK.
/// Manages policy state with atomic reloading and snapshot isolation.
pub struct Guard {
    pub(crate) state: ArcSwap<GuardState>,
}

fn stronger_decision(current: GuardDecision, candidate: GuardDecision) -> GuardDecision {
    fn strength(decision: &GuardDecision) -> u8 {
        match decision {
            GuardDecision::Allow => 0,
            GuardDecision::AskUser { .. } => 1,
            GuardDecision::Deny { .. } => 2,
            // A future decision kind must never weaken an established gate.
            _ => 2,
        }
    }

    if strength(&candidate) > strength(&current) {
        candidate
    } else {
        current
    }
}

struct EvaluatedDecision {
    decision: GuardDecision,
    git_push_intents: Vec<GitPushIntent>,
    /// Set when the anomaly detector produced this decision, so the audit
    /// record can state what the verdict was derived from instead of only
    /// asserting it.
    anomaly_evidence: Option<agent_guard_core::AnomalyEvidence>,
}

impl EvaluatedDecision {
    fn without_git_intents(decision: GuardDecision) -> Self {
        Self {
            decision,
            git_push_intents: Vec::new(),
            anomaly_evidence: None,
        }
    }

    fn with_anomaly_evidence(
        decision: GuardDecision,
        evidence: Option<agent_guard_core::AnomalyEvidence>,
    ) -> Self {
        Self {
            decision,
            git_push_intents: Vec::new(),
            anomaly_evidence: evidence,
        }
    }
}

#[derive(Clone)]
pub(crate) struct GuardState {
    pub(crate) engine: Arc<PolicyEngine>,
    pub(crate) audit_cfg: AuditConfig,
    pub(crate) audit_file_writer: Option<Arc<AuditFileWriter>>,
    pub(crate) siem_exporter: Arc<SiemExporter>,
    pub(crate) anomaly_detector: Arc<crate::anomaly::AnomalyDetector>,
    pub(crate) signing_key: Option<ed25519_dalek::SigningKey>,
    pub(crate) policy_verification: PolicyVerification,
    /// Per-Guard metrics handle; defaults to the process-global registry so
    /// existing scrape setups keep working, but two Guards in one process
    /// can be given separate registries (#60).
    pub(crate) metrics: Arc<crate::metrics::Metrics>,
    pub(crate) audit_sink: AuditSink,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.load();
        f.debug_struct("Guard")
            .field("policy_version", &state.engine.version())
            .field("audit_enabled", &state.audit_cfg.enabled)
            .field("audit_output", &state.audit_cfg.output)
            .finish_non_exhaustive()
    }
}

impl Guard {
    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        self.check_internal(input, &state, &request_id)
    }

    pub fn check_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> GuardDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.check_internal(&input, &state, &request_id)
    }

    pub fn decide(&self, input: &GuardInput) -> RuntimeDecision {
        let state = self.state.load();
        let request_id = Uuid::new_v4().to_string();
        let decision = self.check_internal(input, &state, &request_id);
        runtime_decision_for_input(input, decision)
    }

    pub fn decide_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> RuntimeDecision {
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.decide(&input)
    }

    /// Scan host-supplied input text (e.g. a prompt before it reaches the LLM
    /// provider) against the top-level `input_content:` policy block.
    ///
    /// Unlike the per-tool outbound content path, the Guard does not perform
    /// the call this input is destined for, so Mask mode hands the redacted
    /// text back to the host via `ContentCheckOutcome::masked_text`. Findings
    /// are audited as a `ContentFinding` record with tool label `"input"` for
    /// every mode — including Block, since no ToolCall record exists to carry
    /// an input-scan denial. With no `input_content:` block configured the
    /// text is not scanned and a benign outcome is returned.
    #[cfg(feature = "content")]
    pub fn check_content(
        &self,
        text: &str,
        context: &Context,
    ) -> crate::content_filter::ContentCheckOutcome {
        use crate::content_filter::ContentCheckOutcome;

        let state = self.state.load();
        let Some(policy) = state.engine.input_content_policy() else {
            return ContentCheckOutcome::benign();
        };
        let Some(app) = crate::content_filter::apply_input_content(policy, text) else {
            return ContentCheckOutcome::benign();
        };

        let mode_label = match app.mode {
            agent_guard_core::ContentMode::Block => "block",
            agent_guard_core::ContentMode::Mask => "mask",
            agent_guard_core::ContentMode::Warn => "warn",
        };
        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ContentFinding(
                agent_guard_core::ContentFindingEvent {
                    timestamp: chrono::Utc::now(),
                    request_id: Uuid::new_v4().to_string(),
                    agent_id: context.agent_id.clone(),
                    tool: "input".to_string(),
                    mode: mode_label.to_string(),
                    count: app.labels.len(),
                    labels: app.labels.clone(),
                },
            ));

        ContentCheckOutcome {
            blocked: app.mode == agent_guard_core::ContentMode::Block,
            masked_text: app.masked_text,
            labels: app.labels,
        }
    }

    pub(crate) fn check_internal(
        &self,
        input: &GuardInput,
        state: &GuardState,
        request_id: &str,
    ) -> GuardDecision {
        let metrics = &state.metrics;
        let agent_id = input
            .context
            .agent_id
            .clone()
            .unwrap_or_else(|| "default".to_string());

        metrics
            .policy_checks_total
            .get_or_create(&crate::metrics::ToolLabels {
                agent_id: agent_id.clone(),
                tool: input.tool.name().to_string(),
            })
            .inc();

        let anomaly_subject = anomaly_subject(&input.context);
        let anomaly_cfg = state.engine.anomaly_config();

        let verdict = state.anomaly_detector.check(&anomaly_subject, anomaly_cfg);
        match verdict.status {
            crate::anomaly::AnomalyStatus::Normal => {}
            crate::anomaly::AnomalyStatus::RateLimited => {
                let evaluated = EvaluatedDecision::with_anomaly_evidence(
                    GuardDecision::deny(
                        DecisionCode::AnomalyDetected,
                        format!(
                            "anomaly detected: tool call frequency exceeded limit ({} calls / {}s)",
                            anomaly_cfg.rate_limit.max_calls, anomaly_cfg.rate_limit.window_seconds
                        ),
                    ),
                    verdict.evidence,
                );
                return self
                    .finalize_check(input, &evaluated, state, &agent_id, "deny", request_id);
            }
            crate::anomaly::AnomalyStatus::Locked => {
                let evaluated = EvaluatedDecision::with_anomaly_evidence(
                    GuardDecision::deny(
                        DecisionCode::AgentLocked,
                        "anomaly detected: agent locked due to too many security denials (Deny Fuse)",
                    ),
                    verdict.evidence,
                );
                return self
                    .finalize_check(input, &evaluated, state, &agent_id, "deny", request_id);
            }
        }

        let evaluated = self.evaluate_with_metadata(input, state);
        let decision = &evaluated.decision;

        let outcome = match decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => {
                state
                    .anomaly_detector
                    .report_denial(&anomaly_subject, anomaly_cfg);
                "deny"
            }
            GuardDecision::AskUser { .. } => "ask",
            // Fail closed: label an unrecognized decision as a denial, never allow.
            _ => "deny",
        };
        self.finalize_check(input, &evaluated, state, &agent_id, outcome, request_id)
    }

    fn finalize_check(
        &self,
        input: &GuardInput,
        evaluated: &EvaluatedDecision,
        state: &GuardState,
        agent_id: &str,
        outcome: &str,
        request_id: &str,
    ) -> GuardDecision {
        let decision = &evaluated.decision;
        let metrics = &state.metrics;

        metrics
            .decision_total
            .get_or_create(&crate::metrics::DecisionLabels {
                agent_id: agent_id.to_string(),
                tool: input.tool.name().to_string(),
                outcome: outcome.to_string(),
            })
            .inc();

        if outcome == "deny"
            && matches!(decision, GuardDecision::Deny { reason } if reason.code() == DecisionCode::AnomalyDetected || reason.code() == DecisionCode::AgentLocked)
        {
            metrics
                .anomaly_triggered_total
                .get_or_create(&crate::metrics::ToolLabels {
                    agent_id: agent_id.to_string(),
                    tool: input.tool.name().to_string(),
                })
                .inc();

            let event = agent_guard_core::AnomalyEvent {
                timestamp: chrono::Utc::now(),
                agent_id: Some(agent_id.to_string()),
                actor: input.context.actor.clone(),
                reason: match decision {
                    GuardDecision::Deny { reason } => reason.message().to_string(),
                    _ => "anomaly".to_string(),
                },
                evidence: evaluated.anomaly_evidence.clone(),
            };
            let record = if matches!(decision, GuardDecision::Deny { reason } if reason.code() == DecisionCode::AgentLocked)
            {
                agent_guard_core::AuditRecord::AgentLocked(event)
            } else {
                agent_guard_core::AuditRecord::AnomalyTriggered(event)
            };
            // An anomaly record used to reach the SIEM exporter only, which
            // meant that on a file-audited deployment — the plugin default —
            // the record naming the lock was never written anywhere, and any
            // consumer counting `agent_locked` (guard-verify's report does)
            // was structurally always zero. It goes to both sinks now.
            self.emit_record(state, record);
        }

        // `write_audit` is the single place that gates on `audit_cfg.enabled`.
        self.write_audit(
            input,
            decision,
            &evaluated.git_push_intents,
            state,
            request_id,
        );
        decision.clone()
    }

    pub fn default_sandbox() -> Box<dyn Sandbox> {
        resolve_default_sandbox().0
    }

    pub fn default_sandbox_diagnosis() -> DefaultSandboxDiagnosis {
        resolve_default_sandbox().1
    }

    /// Resolve a sandbox backend by its `sandbox_type()` name (issue #100).
    ///
    /// Known names (case-insensitive): `none`, `linux-seccomp`,
    /// `linux-landlock`, `macos-seatbelt`, `windows-job-object`,
    /// `windows-appcontainer`. A known backend that is not compiled into this
    /// build, or not functional on this host, resolves to the truthful
    /// `"none"` backend instead of claiming isolation it cannot provide —
    /// the same rule as the default selection (GATE 2/5). An unknown name is
    /// a hard error, never a silent noop.
    pub fn sandbox_by_name(name: &str) -> Result<Box<dyn Sandbox>, UnknownBackendError> {
        resolve_sandbox_by_name(name).map(|(sandbox, _)| sandbox)
    }

    pub(crate) fn evaluate(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
        self.evaluate_with_metadata(input, state).decision
    }

    fn evaluate_with_metadata(&self, input: &GuardInput, state: &GuardState) -> EvaluatedDecision {
        let mut bash_policy_subjects = Vec::new();
        let mut parsed_git_pushes = Vec::new();
        let mut validator_warning = None;
        if let Tool::Bash = &input.tool {
            let mode = policy_mode_to_permission_mode(
                &state.engine.effective_mode(&input.tool, &input.context),
            );
            let workspace_path: &Path = input
                .context
                .working_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."));

            let command = match extract_core_bash_command(&input.payload) {
                Ok(ExtractedPayload::Command(command)) => command,
                // The core extractor only yields `Command` for a bash payload, so this
                // arm is unreachable today. It lives in a security-critical evaluation
                // path, so fail closed with a deny rather than panic if that invariant
                // ever changes in the core crate. (Pre-1.0 cleanup, issue #61 item 3.)
                Ok(_) => {
                    return EvaluatedDecision::without_git_intents(GuardDecision::deny(
                        DecisionCode::InvalidPayload,
                        "bash payload did not yield a command string".to_string(),
                    ));
                }
                Err(decision) => return EvaluatedDecision::without_git_intents(decision),
            };

            let escape_paths = state.engine.workspace_escape_paths(&input.tool);
            let result = validate_bash_command(&command, mode, workspace_path, escape_paths);
            match result {
                ValidationResult::Block { reason } => {
                    let code = classify_block_reason(&reason);
                    return EvaluatedDecision::without_git_intents(GuardDecision::deny(
                        code, reason,
                    ));
                }
                ValidationResult::Warn { message } => {
                    validator_warning = Some(GuardDecision::ask(
                        message.clone(),
                        DecisionCode::DestructiveCommand,
                        message,
                    ));
                }
                ValidationResult::Allow => {}
            }

            if let Ok(subjects) = canonical_policy_subjects(&command) {
                bash_policy_subjects.extend(subjects);
            }

            // Match modeled Git pushes and conservative embedded argv candidates
            // by parsed intent as well as by their raw shell spelling. This makes
            // path-qualified executables, transparent wrappers, Git repository
            // selectors, and refspec shorthand share one policy decision. It is
            // additive: canonical evaluation may strengthen Allow → Ask/Deny or
            // Ask → Deny, but never relax a raw or validator decision. Restricted
            // modes already reject a shell parse failure above.
            if let Ok(intents) = git_push_intents(&command) {
                for intent in &intents {
                    for subject in intent.policy_subjects() {
                        if !bash_policy_subjects
                            .iter()
                            .any(|existing| existing == subject)
                        {
                            bash_policy_subjects.push(subject.to_string());
                        }
                    }
                }
                parsed_git_pushes = intents;
            }
        }

        // HttpRequest: block method-override smuggling before the policy engine
        // sees the request, so a benign declared method can't carry a mutating
        // override header past a method-aware rule.
        if let Tool::HttpRequest = &input.tool {
            if let ValidationResult::Block { reason } = validate_http_request(&input.payload) {
                return EvaluatedDecision::without_git_intents(GuardDecision::deny(
                    DecisionCode::DeniedByRule,
                    reason,
                ));
            }
        }

        let mut decision = state
            .engine
            .check(&input.tool, &input.payload, &input.context);
        if let Some(warning) = validator_warning {
            decision = stronger_decision(decision, warning);
        }

        if !matches!(decision, GuardDecision::Deny { .. }) {
            for subject in bash_policy_subjects {
                let canonical_payload = serde_json::json!({ "command": subject }).to_string();
                let canonical = state
                    .engine
                    .check(&input.tool, &canonical_payload, &input.context);
                decision = stronger_decision(decision, canonical);
                if matches!(decision, GuardDecision::Deny { .. }) {
                    break;
                }
            }
        }

        decision = with_git_push_preview(decision, &parsed_git_pushes, &input.context);

        // S6-4b: content-layer enforcement. Only consulted when the action
        // layer already allows the call — a content scan never relaxes an
        // existing deny. Under Block mode, sensitive findings upgrade Allow
        // to Deny. Off by default; compiled only with the `content` feature.
        #[cfg(feature = "content")]
        if matches!(decision, GuardDecision::Allow) {
            if let Some(policy) = state.engine.content_policy(&input.tool) {
                if let Some(content_decision) =
                    crate::content_filter::apply_content_policy(policy, &input.tool, &input.payload)
                {
                    return EvaluatedDecision {
                        decision: content_decision,
                        git_push_intents: parsed_git_pushes,
                        anomaly_evidence: None,
                    };
                }
            }
        }

        EvaluatedDecision {
            decision,
            git_push_intents: parsed_git_pushes,
            anomaly_evidence: None,
        }
    }
}

impl GuardState {
    pub(crate) fn new(
        engine: Arc<PolicyEngine>,
        policy_verification: PolicyVerification,
    ) -> Result<Self, GuardInitError> {
        let audit_cfg = engine.audit_config().clone();
        let audit_file_writer = if audit_cfg.output == "file" {
            if let Some(ref path) = audit_cfg.file_path {
                let writer = AuditFileWriter::open(Path::new(path)).map_err(|e| {
                    GuardInitError::AuditFileOpen {
                        path: path.clone(),
                        source: e,
                    }
                })?;
                Some(Arc::new(writer))
            } else {
                None
            }
        } else {
            None
        };

        let siem_exporter = Arc::new(SiemExporter::new(audit_cfg.clone()));
        let anomaly_detector = Arc::new(crate::anomaly::AnomalyDetector::new());

        Ok(Self {
            engine,
            audit_cfg,
            audit_file_writer,
            siem_exporter,
            anomaly_detector,
            signing_key: None,
            policy_verification,
            metrics: crate::metrics::get_metrics(),
            audit_sink: stdout_audit_sink(),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    const POLICY_A: &str = "version: 1\ndefault_mode: read_only\n";
    const POLICY_B: &str = "version: 1\ndefault_mode: workspace_write\n";

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Regression for #56: `with_signing_key` and policy reload are both
    /// read-modify-write updates of `Guard::state`; whichever writer loses
    /// the race has its update silently overwritten. The setter thread runs
    /// a tight RMW loop so that at the instant the reload stores, a setter
    /// iteration is almost certainly between its own load and store — its
    /// store then resurrects the old engine, and no later iteration brings
    /// the new one back. The final state must hold both the reloaded policy
    /// and the signing key.
    #[test]
    fn concurrent_reload_and_signing_key_updates_are_not_lost() -> Result<(), GuardInitError> {
        const TRIALS: usize = 20;
        const SETTER_ITERATIONS: usize = 100_000;
        const RELOAD_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

        let expected_hash = PolicyEngine::from_yaml_str(POLICY_B)?.hash().to_string();
        // Built once: key derivation is ~100µs and would otherwise dominate
        // each setter iteration, shrinking the load→store window to a sliver
        // of the loop and letting the race go unexercised.
        let key = test_signing_key();

        for trial in 0..TRIALS {
            let guard = Guard::from_yaml(POLICY_A)?;
            let barrier = Barrier::new(2);

            let reload_result = std::thread::scope(|s| {
                let reloader = s.spawn(|| {
                    barrier.wait();
                    std::thread::sleep(RELOAD_DELAY);
                    guard.reload_from_yaml(POLICY_B)
                });
                s.spawn(|| {
                    barrier.wait();
                    for _ in 0..SETTER_ITERATIONS {
                        guard.with_signing_key(key.clone());
                    }
                });
                match reloader.join() {
                    Ok(result) => result,
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            });
            reload_result?;

            let state = guard.state.load();
            assert_eq!(
                state.engine.hash(),
                expected_hash,
                "policy reload lost to concurrent with_signing_key (trial {trial})"
            );
            assert!(
                state.signing_key.is_some(),
                "signing key lost to concurrent policy reload (trial {trial})"
            );
        }
        Ok(())
    }

    /// A `Write` impl backed by a shared buffer so tests can observe what
    /// the Guard sends to its audit sink.
    #[derive(Clone)]
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self.0.lock() {
                Ok(mut inner) => {
                    inner.extend_from_slice(buf);
                    Ok(buf.len())
                }
                Err(_) => Err(std::io::Error::other("shared buffer poisoned")),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// #60: two Guards in one process must not blend counters once given
    /// their own registries; the per-state handle (not the global) is what
    /// the check path increments.
    #[test]
    fn injected_metrics_are_isolated_per_guard() -> Result<(), GuardInitError> {
        let first = Guard::from_yaml(POLICY_A)?;
        let second = Guard::from_yaml(POLICY_A)?;
        let first_metrics = Arc::new(crate::metrics::Metrics::new());
        let second_metrics = Arc::new(crate::metrics::Metrics::new());
        first.set_metrics(first_metrics.clone());
        second.set_metrics(second_metrics.clone());

        let input = GuardInput::new(Tool::Bash, r#"{"command":"ls"}"#);
        let _ = first.check(&input);

        let labels = crate::metrics::ToolLabels {
            agent_id: "default".to_string(),
            tool: "bash".to_string(),
        };
        assert_eq!(
            first_metrics
                .policy_checks_total
                .get_or_create(&labels)
                .get(),
            1
        );
        assert_eq!(
            second_metrics
                .policy_checks_total
                .get_or_create(&labels)
                .get(),
            0,
            "second guard's registry must not see the first guard's checks"
        );
        Ok(())
    }

    // Note: an absent `audit:` section disables auditing entirely
    // (AuditConfig's derived Default), unlike an empty `audit:` section
    // where serde field defaults enable it — so these spell it out.
    const POLICY_AUDIT_A: &str =
        "version: 1\ndefault_mode: read_only\naudit:\n  enabled: true\n  output: stdout\n";
    const POLICY_AUDIT_B: &str =
        "version: 1\ndefault_mode: workspace_write\naudit:\n  enabled: true\n  output: stdout\n";

    /// #60: non-file audit output goes to the injectable sink (not raw
    /// stdout), and the sink survives a policy reload like the signing key.
    #[test]
    fn audit_sink_receives_decision_lines_and_survives_reload() -> Result<(), GuardInitError> {
        let guard = Guard::from_yaml(POLICY_AUDIT_A)?;
        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        guard.set_audit_sink(Box::new(SharedBuf(buffer.clone())));

        let input = GuardInput::new(Tool::Bash, r#"{"command":"ls"}"#);
        let _ = guard.check(&input);
        guard.reload_from_yaml(POLICY_AUDIT_B)?;
        let _ = guard.check(&input);

        let captured = buffer.lock().expect("buffer lock").clone();
        let captured = String::from_utf8(captured).expect("audit lines are utf-8");
        let lines: Vec<&str> = captured.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "one audit line per check, before and after reload; captured: {captured:?}"
        );
        for line in lines {
            assert!(line.starts_with('{'), "audit line is JSONL: {line}");
            assert!(line.contains("bash"), "audit line names the tool: {line}");
        }
        Ok(())
    }

    #[test]
    fn allowed_git_push_keeps_structured_intent_in_audit() -> Result<(), GuardInitError> {
        let guard = Guard::from_yaml(POLICY_AUDIT_B)?;
        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        guard.set_audit_sink(Box::new(SharedBuf(buffer.clone())));

        let input = GuardInput::new(Tool::Bash, r#"{"command":"git push origin main"}"#);
        assert_eq!(guard.check(&input), GuardDecision::Allow);

        let captured = buffer.lock().expect("buffer lock").clone();
        let event: serde_json::Value =
            serde_json::from_slice(&captured).expect("audit line is valid JSON");
        let intent = &event["details"]["git_push_intents"][0];
        assert_eq!(intent["command"], "git push");
        assert_eq!(intent["remote"], "origin");
        assert_eq!(intent["refspecs"], serde_json::json!(["main"]));
        assert_eq!(intent["force"], false);
        Ok(())
    }
}
