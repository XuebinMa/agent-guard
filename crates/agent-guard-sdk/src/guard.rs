use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    payload::{extract_bash_command as extract_core_bash_command, ExtractedPayload},
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    ReloadEvent, RuntimeDecision, Tool,
};
use agent_guard_sandbox::Sandbox;
use agent_guard_validators::bash::{validate_bash_command, ValidationResult};
use arc_swap::ArcSwap;
use thiserror::Error;
use uuid::Uuid;

use crate::audit_writer::AuditFileWriter;
use crate::guard_helpers::{
    anomaly_subject, classify_block_reason, policy_mode_to_permission_mode,
    runtime_decision_for_input,
};
use crate::policy_signing::{
    load_policy_signature_file, load_public_key_file, parse_hex_signing_key, verify_policy,
    PolicyVerification,
};
use crate::sandbox_resolution::resolve_default_sandbox;
pub use crate::sandbox_resolution::DefaultSandboxDiagnosis;
use crate::siem::SiemExporter;

// Backward-compatible re-exports: callers may still reference these via
// `agent_guard_sdk::guard::*` even after the execute/run path moved to the
// sibling `enforce` module.
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

#[derive(Clone)]
pub(crate) struct GuardState {
    pub(crate) engine: Arc<PolicyEngine>,
    pub(crate) audit_cfg: AuditConfig,
    pub(crate) audit_file_writer: Option<Arc<AuditFileWriter>>,
    pub(crate) siem_exporter: Arc<SiemExporter>,
    pub(crate) anomaly_detector: Arc<crate::anomaly::AnomalyDetector>,
    pub(crate) signing_key: Option<ed25519_dalek::SigningKey>,
    pub(crate) policy_verification: PolicyVerification,
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
    /// Create a Guard from an already-parsed PolicyEngine.
    pub fn new(engine: PolicyEngine) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine), PolicyVerification::unsigned())?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    /// Construct a Guard from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_str(yaml)?)
    }

    /// Construct a Guard from a YAML file.
    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_file(path)?)
    }

    /// Construct a Guard from a YAML string and detached Ed25519 signature.
    pub fn from_signed_yaml(
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<Self, GuardInitError> {
        let engine = PolicyEngine::from_yaml_str(yaml)?;
        Self::new_with_verification(engine, verify_policy(yaml, public_key_hex, signature_hex))
    }

    /// Construct a Guard from a YAML file and detached Ed25519 signature file.
    pub fn from_signed_yaml_file(
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<Self, GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        Self::from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    fn new_with_verification(
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine), policy_verification)?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    /// Set the Ed25519 signing key for provenance receipts.
    pub fn with_signing_key(&self, key: ed25519_dalek::SigningKey) {
        // RCU instead of load→clone→store: a plain store racing with a
        // concurrent reload would silently drop one side's update (#56).
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.signing_key = Some(key.clone());
            new_state
        });
    }

    /// Construct a Guard from a YAML string with an Ed25519 signing key for provenance.
    pub fn from_yaml_with_key(
        yaml: &str,
        key: ed25519_dalek::SigningKey,
    ) -> Result<Self, GuardInitError> {
        let guard = Self::from_yaml(yaml)?;
        guard.with_signing_key(key);
        Ok(guard)
    }

    /// Load a hex-encoded Ed25519 private key from a file and set it on this Guard.
    pub fn load_signing_key(&self, path: impl AsRef<Path>) -> Result<(), GuardInitError> {
        let hex_str = std::fs::read_to_string(path)
            .map_err(|e| GuardInitError::SigningKeyLoad(e.to_string()))?;
        let key = parse_hex_signing_key(hex_str.trim()).map_err(GuardInitError::SigningKeyLoad)?;
        self.with_signing_key(key);
        Ok(())
    }

    /// Atomically reload the policy engine from a new instance.
    pub fn reload_engine(&self, engine: PolicyEngine) -> Result<(), GuardInitError> {
        self.reload_engine_with_verification(engine, PolicyVerification::unsigned())
    }

    pub fn reload_engine_with_verification(
        &self,
        engine: PolicyEngine,
        policy_verification: PolicyVerification,
    ) -> Result<(), GuardInitError> {
        let new_version = engine.version().to_string();
        let base_state = GuardState::new(Arc::new(engine), policy_verification)?;

        // The carry-over fields must be copied from the state observed at
        // swap time, not from a snapshot taken earlier: a `with_signing_key`
        // landing between that snapshot and the store would be lost (#56).
        // RCU retries the copy until the swap is uncontended.
        let old_state = self.state.rcu(|current| {
            let mut new_state = base_state.clone();
            new_state.anomaly_detector = current.anomaly_detector.clone();
            new_state.signing_key = current.signing_key.clone();
            new_state
        });

        let event = ReloadEvent::success(old_state.engine.version().to_string(), new_version);
        self.write_reload_audit(&event, &old_state);

        Ok(())
    }

    /// Atomically reload the policy from a YAML string.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine(engine),
            Err(e) => {
                let old_state = self.state.load();
                let old_version = old_state.engine.version().to_string();
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    pub fn reload_from_signed_yaml(
        &self,
        yaml: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine_with_verification(
                engine,
                verify_policy(yaml, public_key_hex, signature_hex),
            ),
            Err(e) => {
                let old_state = self.state.load();
                let old_version = old_state.engine.version().to_string();
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    pub fn reload_from_signed_yaml_file(
        &self,
        policy_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
        signature_path: impl AsRef<Path>,
    ) -> Result<(), GuardInitError> {
        let yaml = std::fs::read_to_string(policy_path)
            .map_err(|error| GuardInitError::SigningKeyLoad(error.to_string()))?;
        let public_key_hex =
            load_public_key_file(public_key_path).map_err(GuardInitError::SigningKeyLoad)?;
        let signature_hex =
            load_policy_signature_file(signature_path).map_err(GuardInitError::SigningKeyLoad)?;
        self.reload_from_signed_yaml(&yaml, &public_key_hex, &signature_hex)
    }

    /// Return the current policy version (alias for version)
    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    /// Return the SHA-256 hash of the currently loaded policy.
    pub fn policy_hash(&self) -> String {
        self.state.load().engine.hash().to_string()
    }

    pub fn policy_verification(&self) -> PolicyVerification {
        self.state.load().policy_verification.clone()
    }

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

    pub(crate) fn check_internal(
        &self,
        input: &GuardInput,
        state: &GuardState,
        request_id: &str,
    ) -> GuardDecision {
        let metrics = crate::metrics::get_metrics();
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

        match state.anomaly_detector.check(&anomaly_subject, anomaly_cfg) {
            crate::anomaly::AnomalyStatus::Normal => {}
            crate::anomaly::AnomalyStatus::RateLimited => {
                let decision = GuardDecision::deny(
                    DecisionCode::AnomalyDetected,
                    format!(
                        "anomaly detected: tool call frequency exceeded limit ({} calls / {}s)",
                        anomaly_cfg.rate_limit.max_calls, anomaly_cfg.rate_limit.window_seconds
                    ),
                );
                return self.finalize_check(input, &decision, state, &agent_id, "deny", request_id);
            }
            crate::anomaly::AnomalyStatus::Locked => {
                let decision = GuardDecision::deny(
                    DecisionCode::AgentLocked,
                    "anomaly detected: agent locked due to too many security denials (Deny Fuse)",
                );
                return self.finalize_check(input, &decision, state, &agent_id, "deny", request_id);
            }
        }

        let decision = self.evaluate(input, state);

        let outcome = match &decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => {
                state
                    .anomaly_detector
                    .report_denial(&anomaly_subject, anomaly_cfg);
                "deny"
            }
            GuardDecision::AskUser { .. } => "ask",
        };
        self.finalize_check(input, &decision, state, &agent_id, outcome, request_id)
    }

    fn finalize_check(
        &self,
        input: &GuardInput,
        decision: &GuardDecision,
        state: &GuardState,
        agent_id: &str,
        outcome: &str,
        request_id: &str,
    ) -> GuardDecision {
        let metrics = crate::metrics::get_metrics();

        metrics
            .decision_total
            .get_or_create(&crate::metrics::DecisionLabels {
                agent_id: agent_id.to_string(),
                tool: input.tool.name().to_string(),
                outcome: outcome.to_string(),
            })
            .inc();

        if outcome == "deny"
            && matches!(decision, GuardDecision::Deny { reason } if reason.code == DecisionCode::AnomalyDetected || reason.code == DecisionCode::AgentLocked)
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
                    GuardDecision::Deny { reason } => reason.message.clone(),
                    _ => "anomaly".to_string(),
                },
            };
            let record = if matches!(decision, GuardDecision::Deny { reason } if reason.code == DecisionCode::AgentLocked)
            {
                agent_guard_core::AuditRecord::AgentLocked(event)
            } else {
                agent_guard_core::AuditRecord::AnomalyTriggered(event)
            };
            state.siem_exporter.export(record);
        }

        // `write_audit` is the single place that gates on `audit_cfg.enabled`.
        self.write_audit(input, decision, state, request_id);
        decision.clone()
    }

    pub fn default_sandbox() -> Box<dyn Sandbox> {
        resolve_default_sandbox().0
    }

    pub fn default_sandbox_diagnosis() -> DefaultSandboxDiagnosis {
        resolve_default_sandbox().1
    }

    fn evaluate(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
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
                Ok(_) => unreachable!("core bash extractor returned a non-command payload"),
                Err(decision) => return decision,
            };

            let escape_paths = state.engine.workspace_escape_paths(&input.tool);
            let result = validate_bash_command(&command, mode, workspace_path, escape_paths);
            match result {
                ValidationResult::Block { reason } => {
                    let code = classify_block_reason(&reason);
                    return GuardDecision::deny(code, reason);
                }
                ValidationResult::Warn { message } => {
                    return GuardDecision::ask(
                        message.clone(),
                        DecisionCode::DestructiveCommand,
                        message,
                    );
                }
                ValidationResult::Allow => {}
            }
        }

        let decision = state
            .engine
            .check(&input.tool, &input.payload, &input.context);

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
                    return content_decision;
                }
            }
        }

        decision
    }

    fn write_audit(
        &self,
        input: &GuardInput,
        decision: &GuardDecision,
        state: &GuardState,
        request_id: &str,
    ) {
        if !state.audit_cfg.enabled {
            return;
        }

        let event = AuditEvent::from_decision(
            request_id.to_string(),
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
            state.audit_cfg.include_payload_hash,
            state.engine.version().to_string(),
        );
        let line = event.to_jsonl();

        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::ToolCall(event));

        if state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                writer.send(line);
            }
        } else {
            println!("{}", line);
        }
    }

    fn write_reload_audit(&self, event: &ReloadEvent, state: &GuardState) {
        let line = event.to_jsonl();
        state
            .siem_exporter
            .export(agent_guard_core::AuditRecord::PolicyReload(event.clone()));

        if state.audit_cfg.enabled && state.audit_cfg.output == "file" {
            if let Some(ref writer) = state.audit_file_writer {
                writer.send(line);
            }
        }
    }
}

impl GuardState {
    fn new(
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
}
