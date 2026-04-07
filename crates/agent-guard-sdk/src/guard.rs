use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    PolicyMode, ReloadEvent, ReloadStatus, Tool,
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
    /// Returns Err if audit output=file and the file cannot be opened.
    pub fn new(engine: PolicyEngine) -> Result<Self, GuardInitError> {
        let state = GuardState::new(Arc::new(engine))?;
        Ok(Self {
            state: ArcSwap::from_pointee(state),
        })
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_str(yaml)?)
    }

    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_file(path)?)
    }

    /// Atomically reload the policy engine from a new instance.
    /// If the new engine's audit configuration is different, the audit file
    /// will be opened/updated accordingly.
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

    pub fn policy_version(&self) -> String {
        self.state.load().engine.version().to_string()
    }

    pub fn policy_hash(&self) -> String {
        self.policy_version()
    }

    /// Evaluate the guard decision for a tool call.
    ///
    /// Decision pipeline (in order):
    /// 1. Bash validator (for Tool::Bash) — catches destructive/read-only/path violations.
    /// 2. PolicyEngine — applies YAML policy rules (deny/ask/allow/paths/trust).
    ///
    /// Emits an audit event after the final decision if auditing is enabled.
    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        // M3.2: Take a snapshot of the current state at the start of the request.
        let state = self.state.load();
        self.check_internal(input, &state)
    }

    /// Internal version of check that uses a specific state snapshot.
    fn check_internal(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
        let decision = self.evaluate(input, state);
        if state.audit_cfg.enabled {
            self.write_audit(input, &decision, state);
        }
        decision
    }

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

    pub fn execute(
        &self,
        input: &GuardInput,
        sandbox: &dyn Sandbox,
    ) -> ExecuteResult {
        // M3.2: Single snapshot for the entire execute() flow.
        let state = self.state.load();

        let decision = self.check_internal(input, &state);
        match &decision {
            GuardDecision::Allow { .. } => {}
            GuardDecision::Deny { .. } => {
                return Ok(ExecuteOutcome::Denied { decision });
            }
            GuardDecision::AskUser { .. } => {
                return Ok(ExecuteOutcome::AskRequired { decision });
            }
        }

        // Extract the command string from the JSON payload.
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

        let output = sandbox.execute(&command, &ctx)?;
        Ok(ExecuteOutcome::Executed { output })
    }

    /// Convenience helper to execute a command using the Noop sandbox (passthrough).
    pub fn execute_noop(&self, input: &GuardInput) -> ExecuteResult {
        let sandbox = agent_guard_sandbox::NoopSandbox;
        self.execute(input, &sandbox)
    }

    fn evaluate(&self, input: &GuardInput, state: &GuardState) -> GuardDecision {
        // A5: Run bash validator before policy engine for Bash tool calls.
        if let Tool::Bash = &input.tool {
            // Use the policy engine as the single source of truth for mode resolution.
            let mode = policy_mode_to_permission_mode(
                &state.engine.effective_mode(&input.tool, &input.context),
            );
            let workspace_path: &Path = input
                .context
                .working_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."));

            // Extract the actual command from the JSON payload before validating.
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

        // Run the policy engine (handles all tools).
        state.engine.check(&input.tool, &input.payload, &input.context)
    }

    fn write_audit(&self, input: &GuardInput, decision: &GuardDecision, state: &GuardState) {
        let request_id = Uuid::new_v4().to_string();
        let include_hash = state.audit_cfg.include_payload_hash;
        let event = AuditEvent::from_decision(
            request_id,
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
            include_hash,
            state.engine.version().to_string(),
        );
        let line = event.to_jsonl();

        if state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                match mutex.lock() {
                    Ok(mut file) => {
                        use std::io::Write;
                        if let Err(e) = writeln!(file, "{}", line) {
                            eprintln!("[agent-guard] AUDIT WRITE ERROR: {e} (record: {line})");
                        }
                    }
                    Err(e) => {
                        eprintln!("[agent-guard] AUDIT MUTEX POISONED: {e}");
                    }
                }
            }
        } else {
            println!("{}", line);
        }
    }

    fn write_reload_audit(&self, event: &ReloadEvent, state: &GuardState) {
        let line = event.to_jsonl();
        eprintln!("[agent-guard] POLICY RELOAD {}: {}", 
            match event.status {
                ReloadStatus::Success => "SUCCESS",
                ReloadStatus::Failure => "FAILURE",
            },
            line
        );

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

#[cfg(test)]
mod tests {
    use super::*;
    use agent_guard_core::{Context, GuardInput, Tool, TrustLevel, GuardDecision};
    use std::sync::Arc;

    #[test]
    fn test_reload_success() {
        let yaml1 = r#"
version: 1
default_mode: read_only
"#;
        let yaml2 = r#"
version: 1
default_mode: workspace_write
"#;

        let guard = Guard::from_yaml(yaml1).unwrap();
        let ctx = Context {
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        };
        
        // Check old policy (read_only)
        let res = guard.check_tool(Tool::Bash, r#"{"command":"touch test"}"#, ctx.clone());
        assert!(matches!(res, GuardDecision::Deny { .. }), "Old policy should deny write");
        
        // Reload
        guard.reload_from_yaml(yaml2).expect("Reload should succeed");
        
        // Check new policy (workspace_write)
        let res = guard.check_tool(Tool::Bash, r#"{"command":"touch test"}"#, ctx);
        assert!(matches!(res, GuardDecision::Allow), "New policy should allow write");
    }

    #[test]
    fn test_reload_failure_preserves_old_policy() {
        let yaml1 = r#"
version: 1
default_mode: read_only
"#;
        let yaml_bad = "invalid: yaml: : :";

        let guard = Guard::from_yaml(yaml1).unwrap();
        let ctx = Context {
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        };
        
        // Reload fails
        let res = guard.reload_from_yaml(yaml_bad);
        assert!(res.is_err(), "Invalid YAML should fail reload");
        
        // Old policy still active
        let res = guard.check_tool(Tool::Bash, r#"{"command":"touch test"}"#, ctx);
        assert!(matches!(res, GuardDecision::Deny { .. }), "Old policy should still be active after failed reload");
    }

    #[test]
    fn test_execute_snapshot_isolation() {
        // This test ensures that execute() uses a consistent snapshot even if 
        // a reload happens in the middle of its execution.
        let yaml1 = r#"
version: 1
default_mode: read_only
"#;
        let yaml2 = r#"
version: 1
default_mode: workspace_write
"#;

        let guard = Guard::from_yaml(yaml1).unwrap();
        let guard_arc = Arc::new(guard);
        
        let ctx = Context {
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        };
        let input = GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"touch test"}"#.to_string(),
            context: ctx,
        };

        // 1. Manually load state to simulate the start of execute()
        let state_snapshot = guard_arc.state.load();
        
        // 2. Perform reload
        guard_arc.reload_from_yaml(yaml2).unwrap();
        
        // 3. Verify that check_internal using the OLD snapshot still denies
        let res_old = guard_arc.check_internal(&input, &state_snapshot);
        assert!(matches!(res_old, GuardDecision::Deny { .. }), "Old snapshot should still deny");
        
        // 4. Verify that a new check() uses the NEW snapshot and allows
        let res_new = guard_arc.check(&input);
        assert!(matches!(res_new, GuardDecision::Allow), "New request should allow");
    }
}
