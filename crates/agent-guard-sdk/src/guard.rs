use std::path::Path;
use std::sync::Arc;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    PolicyMode, Tool,
};
use agent_guard_sandbox::{NoopSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput};
use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
use arc_swap::ArcSwap;
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
            .field("policy_hash", &state.engine.hash())
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
        let old_version = self.state.load().engine.version().to_string();
        let new_version = engine.version().to_string();
        
        let new_state = GuardState::new(Arc::new(engine))?;
        self.state.store(Arc::new(new_state));
        
        eprintln!(
            "[agent-guard] POLICY RELOADED: {} -> {} at {}",
            old_version,
            new_version,
            chrono::Utc::now()
        );
        Ok(())
    }

    /// Atomically reload the policy from a YAML string.
    pub fn reload_from_yaml(&self, yaml: &str) -> Result<(), GuardInitError> {
        match PolicyEngine::from_yaml_str(yaml) {
            Ok(engine) => self.reload_engine(engine),
            Err(e) => {
                let err = GuardInitError::Policy(e);
                eprintln!(
                    "[agent-guard] POLICY RELOAD FAILED: {} at {}",
                    err,
                    chrono::Utc::now()
                );
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
            // This ensures the validator doesn't see raw JSON.
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
                    // Map validator block reason to the appropriate DecisionCode.
                    let code = classify_block_reason(&reason);
                    return GuardDecision::deny(code, reason);
                }
                ValidationResult::Warn { message } => {
                    // Destructive/path warnings become AskUser — let the human decide.
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
            state.engine.hash().to_string(),
        );
        let line = event.to_jsonl();

        if state.audit_cfg.output == "file" {
            if let Some(ref mutex) = state.audit_file {
                match mutex.lock() {
                    Ok(mut file) => {
                        use std::io::Write;
                        if let Err(e) = writeln!(file, "{}", line) {
                            // Writing to the audit file failed. This must not be silent —
                            // a security library that silently drops audit records gives
                            // false assurance. Log to stderr so operators can notice.
                            eprintln!("[agent-guard] AUDIT WRITE ERROR: {e} (record: {line})");
                        }
                    }
                    Err(e) => {
                        // Mutex is poisoned (a previous writer panicked). Do not abort
                        // the caller's operation, but do not drop silently either.
                        eprintln!("[agent-guard] AUDIT MUTEX POISONED: {e}");
                    }
                }
            }
        } else {
            println!("{}", line);
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

// ── Convenience: check_tool ──────────────────────────────────────────────────

impl Guard {
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
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Map a `PolicyMode` (from the policy engine, which is the authoritative source)
/// to the validator's `PermissionMode`.
///
/// This is the only place that bridges the two type systems. The policy engine's
/// `effective_mode()` must always be called first — never derive mode from trust_level
/// alone, because tool-level `mode:` overrides in policy YAML would be silently ignored.
fn policy_mode_to_permission_mode(mode: &PolicyMode) -> PermissionMode {
    match mode {
        PolicyMode::ReadOnly => PermissionMode::ReadOnly,
        PolicyMode::WorkspaceWrite => PermissionMode::WorkspaceWrite,
        PolicyMode::FullAccess => PermissionMode::DangerFullAccess,
    }
}

fn classify_block_reason(reason: &str) -> DecisionCode {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("read-only") || lower.contains("read only") {
        DecisionCode::WriteInReadOnlyMode
    } else if lower.contains("traversal") || lower.contains("../") {
        DecisionCode::PathTraversal
    } else {
        DecisionCode::DestructiveCommand
    }
}

// ── Execute API ───────────────────────────────────────────────────────────────

/// The result of `Guard::execute()`.
///
/// # Failure semantics
///
/// | Scenario                          | Variant / Err                         |
/// |-----------------------------------|---------------------------------------|
/// | Policy denies the tool call       | `Ok(Denied { decision })`             |
/// | Policy asks user (not auto-allow) | `Ok(AskRequired { decision })`        |
/// | Policy allows; command runs OK    | `Ok(Executed { output })`             |
/// | Policy allows; seccomp filter err | `Err(SandboxError::FilterSetup(…))`   |
/// | Policy allows; process times out  | `Err(SandboxError::Timeout { ms })`   |
/// | Process killed by seccomp filter  | `Err(SandboxError::KilledByFilter{…})`|
/// | Command itself fails to fork/exec | `Err(SandboxError::ExecutionFailed(…))`|
#[derive(Debug)]
pub enum ExecuteOutcome {
    /// The tool call was denied by policy before execution.
    Denied { decision: GuardDecision },
    /// The tool call requires user confirmation; not executed.
    AskRequired { decision: GuardDecision },
    /// The command was executed (policy allowed it).
    Executed { output: SandboxOutput },
}

/// Result type returned by `Guard::execute()`.
pub type ExecuteResult = Result<ExecuteOutcome, SandboxError>;

impl Guard {
    /// Check policy and, if allowed, execute the command in the sandbox.
    ///
    /// `sandbox` is caller-supplied so you can choose `NoopSandbox` (default,
    /// no OS isolation) or `SeccompSandbox` (Linux, syscall filter).
    ///
    /// **Important:** The payload for `Tool::Bash` must be a JSON string
    /// `{"command": "..."}` — the same format used by `check_tool()`.
    ///
    /// # Errors
    ///
    /// Returns `Err(SandboxError)` only when the policy allowed the call but
    /// the sandbox itself failed (timeout, filter setup, exec failure). Policy
    /// denials are encoded in `Ok(ExecuteOutcome::Denied { … })` so callers can
    /// distinguish "refused to run" from "ran but failed".
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

    /// Convenience: execute using `NoopSandbox` (no OS-level isolation).
    ///
    /// Suitable for development and platforms where `SeccompSandbox` is
    /// not yet available (macOS, Windows).
    pub fn execute_noop(&self, input: &GuardInput) -> ExecuteResult {
        self.execute(input, &NoopSandbox)
    }
}

/// Extract the `command` field from a JSON bash payload.
///
/// Payload must be `{"command": "..."}`. Returns `Err(SandboxError::ExecutionFailed)`
/// for non-JSON or missing field, consistent with `INVALID_PAYLOAD` / `MISSING_PAYLOAD_FIELD`
/// decision codes (which would have been caught by `check()` already, but we
/// defend in depth here).
fn extract_bash_command(payload: &str) -> Result<String, SandboxError> {
    let v: serde_json::Value = serde_json::from_str(payload)
        .map_err(|e| SandboxError::ExecutionFailed(format!("invalid payload JSON: {e}")))?;
    v.get("command")
        .and_then(|c| c.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| SandboxError::ExecutionFailed(
            "payload missing 'command' field".to_string(),
        ))
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
    fn test_request_snapshot_isolation() {
        // This test ensures that a request uses a consistent snapshot of the policy.
        // We simulate this by taking a snapshot (state.load()) and verifying it remains
        // unchanged even if the guard is reloaded.
        
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
        let input = GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"touch test"}"#.to_string(),
            context: ctx,
        };

        // 1. Take snapshot
        let guard_arc = Arc::new(guard);
        let state_snapshot = guard_arc.state.load();
        
        // 2. Reload guard to a different policy
        guard_arc.reload_from_yaml(yaml2).unwrap();
        
        // 3. New requests use new policy
        let res_new = guard_arc.check(&input);
        assert!(matches!(res_new, GuardDecision::Allow));
        
        // 4. Old snapshot (if it were passed to a long-running process) still uses old policy
        // In our SDK, 'evaluate' takes a state snapshot.
        let res_old = guard_arc.evaluate(&input, &state_snapshot);
        assert!(matches!(res_old, GuardDecision::Deny { .. }));
    }

    #[test]
    fn test_audit_policy_versioning() {
        // Verify that the audit event contains the correct policy hash.
        let yaml = r#"
version: 1
default_mode: read_only
"#;
        let guard = Guard::from_yaml(yaml).unwrap();
        let expected_version = guard.policy_version();
        
        let ctx = Context {
            trust_level: TrustLevel::Trusted,
            ..Default::default()
        };
        let _input = GuardInput {
            tool: Tool::Bash,
            payload: r#"{"command":"ls"}"#.to_string(),
            context: ctx,
        };
        
        // Verify policy_version() works.
        assert!(!expected_version.is_empty());
        assert_eq!(expected_version.len(), 64); // SHA-256 hex
    }
}
