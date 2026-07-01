use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    payload::{extract_bash_command as extract_core_bash_command, ExtractedPayload},
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    ReloadEvent, RuntimeDecision, Tool,
};
use agent_guard_sandbox::Sandbox;
use agent_guard_validators::bash::{validate_bash_command, ValidationResult};
use agent_guard_validators::http::validate_http_request;
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

/// Destination for non-file audit lines. Defaults to stdout; hosts and
/// tests can redirect it via `Guard::set_audit_sink` so the library never
/// owns the process stdout outright.
pub(crate) type AuditSink = Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>;

fn stdout_audit_sink() -> AuditSink {
    Arc::new(std::sync::Mutex::new(Box::new(std::io::stdout())))
}

/// Write one audit line to the sink. An unwritable sink must not panic or
/// abort the decision path; the failure is surfaced via tracing and the
/// SIEM export remains the durable channel.
fn write_to_audit_sink(sink: &AuditSink, line: &str) {
    use std::io::Write;
    match sink.lock() {
        Ok(mut writer) => {
            if let Err(error) = writeln!(writer, "{line}") {
                tracing::error!(%error, "failed to write audit line to sink");
            }
        }
        Err(_) => {
            tracing::error!("audit sink mutex poisoned; audit line dropped from sink output");
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

    /// Route this Guard's metrics to a dedicated registry instead of the
    /// process-global one, so co-resident Guards don't blend counters (#60).
    pub fn set_metrics(&self, metrics: Arc<crate::metrics::Metrics>) {
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.metrics = metrics.clone();
            new_state
        });
    }

    /// Redirect non-file audit output (default: process stdout). Survives
    /// policy reloads, like the signing key (#60).
    pub fn set_audit_sink(&self, sink: Box<dyn std::io::Write + Send>) {
        let sink: AuditSink = Arc::new(std::sync::Mutex::new(sink));
        self.state.rcu(|current| {
            let mut new_state = (**current).clone();
            new_state.audit_sink = sink.clone();
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
            new_state.metrics = current.metrics.clone();
            new_state.audit_sink = current.audit_sink.clone();
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

    /// Return the version string of the currently loaded policy.
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
            // Fail closed: label an unrecognized decision as a denial, never allow.
            _ => "deny",
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
            };
            let record = if matches!(decision, GuardDecision::Deny { reason } if reason.code() == DecisionCode::AgentLocked)
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
                // The core extractor only yields `Command` for a bash payload, so this
                // arm is unreachable today. It lives in a security-critical evaluation
                // path, so fail closed with a deny rather than panic if that invariant
                // ever changes in the core crate. (Pre-1.0 cleanup, issue #61 item 3.)
                Ok(_) => {
                    return GuardDecision::deny(
                        DecisionCode::InvalidPayload,
                        "bash payload did not yield a command string".to_string(),
                    );
                }
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

        // HttpRequest: block method-override smuggling before the policy engine
        // sees the request, so a benign declared method can't carry a mutating
        // override header past a method-aware rule.
        if let Tool::HttpRequest = &input.tool {
            if let ValidationResult::Block { reason } = validate_http_request(&input.payload) {
                return GuardDecision::deny(DecisionCode::DeniedByRule, reason);
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
            write_to_audit_sink(&state.audit_sink, &line);
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
}
