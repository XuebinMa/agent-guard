use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    PolicyMode, ReloadEvent, Tool,
};
use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use arc_swap::ArcSwap;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

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
}

// ── Guard ─────────────────────────────────────────────────────────────────────

/// Main entry point for the agent-guard SDK.
/// Manages policy state with atomic reloading and snapshot isolation.
pub struct Guard {
    state: ArcSwap<GuardState>,
}

struct GuardState {
    engine: Arc<PolicyEngine>,
    audit_cfg: AuditConfig,
    audit_file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
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
        let state = GuardState::new(Arc::new(engine))?;
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

    /// Atomically reload the policy engine from a new instance.
    pub fn reload_engine(&self, engine: PolicyEngine) -> Result<(), GuardInitError> {
        let old_state = self.state.load();
        let old_version = old_state.engine.version().to_string();
        let new_version = engine.version().to_string();
        
        let new_state = GuardState::new(Arc::new(engine))?;
        self.state.store(Arc::new(new_state));
        
        let event = ReloadEvent::success(old_version, new_version);
        self.write_reload_audit(&event, &old_state);

        Ok(())
    }

    /// Atomically reload the policy from a YAML string.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), GuardInitError> {
        let old_state = self.state.load();
        let old_version = old_state.engine.version().to_string();

        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine(engine),
            Err(e) => {
                let err = GuardInitError::Policy(e);
                let event = ReloadEvent::failure(old_version, err.to_string());
                self.write_reload_audit(&event, &old_state);
                Err(err)
            }
        }
    }

    /// Return the SHA-256 version hash of the currently loaded policy.
    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    /// [Deprecated] alias for policy_version().
    pub fn policy_hash(&self) -> String {
        self.policy_version()
    }

    /// Evaluate the guard decision for a tool call.
    /// Captures the policy state exactly once for the entire request flow.
    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        let state = self.state.load();
        self.check_internal(input, &state)
    }

    /// Higher-level check that accepts tool/payload/context.
    pub fn check_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> GuardDecision {
        let state = self.state.load();
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.check_internal(&input, &state)
    }

    /// Internal core logic that MUST use a captured state snapshot.
    /// This ensures decision, auditing, and execution use the same policy version.
    fn check_internal(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
        // M4.3: Anomaly detection
        let actor = input.context.actor.as_deref().unwrap_or("unknown");
        if crate::anomaly::get_detector().check(actor) {
            let decision = GuardDecision::deny(
                DecisionCode::AnomalyDetected,
                "anomaly detected: high tool call frequency",
            );
            if state.audit_cfg.enabled {
                self.write_audit(input, &decision, state);
            }
            return decision;
        }

        let decision = self.evaluate(input, state);
        
        // M4.2: Record metrics
        let outcome = match &decision {
            GuardDecision::Allow => "allow",
            GuardDecision::Deny { .. } => "deny",
            GuardDecision::AskUser { .. } => "ask",
        };
        crate::metrics::get_metrics().policy_checks.get_or_create(&crate::metrics::DecisionLabels {
            tool: input.tool.name().to_string(),
            outcome: outcome.to_string(),
        }).inc();

        if state.audit_cfg.enabled {
            self.write_audit(input, &decision, state);
        }
        decision
    }

    /// High-level execution method that enforces policy and runs the tool in a sandbox.
    /// Implements single-snapshot isolation (M3.2).
    pub fn execute(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
    ) -> ExecuteResult {
        // M3.2: Capture state snapshot EXACTLY ONCE at the entry point.
        let state = self.state.load();

        // Use the snapshot for decision, auditing, mode calculation, and execution.
        let decision = self.check_internal(input, &state);
        match &decision {
            GuardDecision::Allow => {}
            GuardDecision::Deny { .. } => {
                return Ok(ExecuteOutcome::Denied { decision });
            }
            GuardDecision::AskUser { .. } => {
                return Ok(ExecuteOutcome::AskRequired { decision });
            }
        }

        let command = extract_bash_command(&input.payload)?;
        let mode = state.engine.effective_mode(&input.tool, &input.context);
        let working_directory = input
            .context
            .working_directory
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let ctx = SandboxContext {
            mode,
            working_directory,
            timeout_ms: None,
        };

        let start = std::time::Instant::now();
        let output = sandbox.execute(&command, &ctx)?;
        let duration = start.elapsed().as_secs_f64();

        // M4.2: Record execution duration
        crate::metrics::get_metrics().execution_duration.get_or_create(&crate::metrics::ExecutionLabels {
            tool: input.tool.name().to_string(),
            sandbox: sandbox.name().to_string(),
        }).observe(duration);

        Ok(ExecuteOutcome::Executed { output })
    }

    /// Convenience helper to execute a command using the best available sandbox.
    pub fn execute_default(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = Self::default_sandbox();
        self.execute(input, sandbox.as_ref())
    }

    /// Convenience helper to execute a command using the Noop sandbox.
    pub fn execute_noop(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = agent_guard_sandbox::NoopSandbox;
        self.execute(input, &sandbox)
    }

    /// Returns the best available sandbox for the current platform.
    pub fn default_sandbox() -> Box<dyn Sandbox> {
        #[cfg(target_os = "linux")]
        {
            Box::new(agent_guard_sandbox::SeccompSandbox::new())
        }
        #[cfg(feature = "macos-sandbox")]
        {
            Box::new(agent_guard_sandbox::SeatbeltSandbox)
        }
        #[cfg(feature = "windows-sandbox")]
        {
            Box::new(agent_guard_sandbox::JobObjectSandbox)
        }
        #[cfg(not(any(target_os = "linux", feature = "macos-sandbox", feature = "windows-sandbox")))]
        {
            Box::new(agent_guard_sandbox::NoopSandbox)
        }
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

            let v: serde_json::Value = match serde_json::from_str(&input.payload) {
                Ok(v) => v,
                Err(_) => return GuardDecision::deny(DecisionCode::InvalidPayload, "invalid payload JSON"),
            };
            let command = match v.get("command").and_then(|c| c.as_str()) {
                Some(s) => s,
                None => return GuardDecision::deny(DecisionCode::MissingPayloadField, "payload missing 'command' field"),
            };

            let result = validate_bash_command(command, mode, workspace_path);
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

        state.engine.check(&input.tool, &input.payload, &input.context)
    }

    fn write_audit(&self, input: &GuardInput, decision: &GuardDecision, state: &GuardState) {
        let request_id = Uuid::new_v4().to_string();
        let event = AuditEvent::from_decision(
            request_id,
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

        if state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                if let Ok(mut file) = mutex.lock() {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", line);
                }
            }
        } else {
            println!("{}", line);
        }
    }

    fn write_reload_audit(&self, event: &ReloadEvent, state: &GuardState) {
        let line = event.to_jsonl();
        if state.audit_cfg.enabled && state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                if let Ok(mut file) = mutex.lock() {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", line);
                }
            }
        }
    }
}

impl GuardState {
    fn new(engine: Arc<PolicyEngine>) -> Result<Self, GuardInitError> {
        let audit_cfg = engine.audit_config().clone();
        let audit_file = if audit_cfg.output == "file" {
            if let Some(ref path) = audit_cfg.file_path {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| GuardInitError::AuditFileOpen {
                        path: path.clone(),
                        source: e,
                    })?;
                Some(Arc::new(std::sync::Mutex::new(f)))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            engine,
            audit_cfg,
            audit_file,
        })
    }
}

// ── ExecuteResult ─────────────────────────────────────────────────────────────

pub type ExecuteResult = Result<ExecuteOutcome, SandboxError>;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExecuteOutcome {
    Executed { output: SandboxOutput },
    Denied { decision: GuardDecision },
    AskRequired { decision: GuardDecision },
}

fn extract_bash_command(payload: &str) -> Result<String, SandboxError> {
    let v: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| SandboxError::ExecutionFailed("invalid payload JSON".to_string()))?;
    v.get("command")
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| SandboxError::ExecutionFailed("payload missing 'command' field".to_string()))
}

fn policy_mode_to_permission_mode(mode: &PolicyMode) -> PermissionMode {
    match mode {
        PolicyMode::ReadOnly => PermissionMode::ReadOnly,
        PolicyMode::WorkspaceWrite => PermissionMode::WorkspaceWrite,
        PolicyMode::FullAccess => PermissionMode::DangerFullAccess,
    }
}

fn classify_block_reason(reason: &str) -> DecisionCode {
    if reason.contains("read-only mode") {
        DecisionCode::WriteInReadOnlyMode
    } else if reason.contains("destructive") {
        DecisionCode::DestructiveCommand
    } else if reason.contains("outside workspace") {
        DecisionCode::PathOutsideWorkspace
    } else {
        DecisionCode::DeniedByRule
    }
}
