use std::path::Path;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    PolicyMode, Tool,
};
use agent_guard_sandbox::{NoopSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput};
use agent_guard_validators::bash::{validate_bash_command, PermissionMode, ValidationResult};
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
    engine: PolicyEngine,
    audit_cfg: AuditConfig,
    // Mutex wrapping is not Debug-able automatically; we implement Debug manually.
    audit_file: Option<std::sync::Mutex<std::fs::File>>,
}

impl std::fmt::Debug for Guard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guard")
            .field("audit_enabled", &self.audit_cfg.enabled)
            .field("audit_output", &self.audit_cfg.output)
            .finish_non_exhaustive()
    }
}

impl Guard {
    /// Create a Guard from an already-parsed PolicyEngine.
    /// Returns Err if audit output=file and the file cannot be opened.
    pub fn new(engine: PolicyEngine) -> Result<Self, GuardInitError> {
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
                Some(std::sync::Mutex::new(f))
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

    pub fn from_yaml(yaml: &str) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_str(yaml)?)
    }

    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, GuardInitError> {
        Self::new(PolicyEngine::from_yaml_file(path)?)
    }

    /// Evaluate the guard decision for a tool call.
    ///
    /// Decision pipeline (in order):
    /// 1. Bash validator (for Tool::Bash) — catches destructive/read-only/path violations.
    /// 2. PolicyEngine — applies YAML policy rules (deny/ask/allow/paths/trust).
    ///
    /// Emits an audit event after the final decision if auditing is enabled.
    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        let decision = self.evaluate(input);
        if self.audit_cfg.enabled {
            self.write_audit(input, &decision);
        }
        decision
    }

    fn evaluate(&self, input: &GuardInput) -> GuardDecision {
        // A5: Run bash validator before policy engine for Bash tool calls.
        if let Tool::Bash = &input.tool {
            // Use the policy engine as the single source of truth for mode resolution.
            let mode = policy_mode_to_permission_mode(
                &self.engine.effective_mode(&input.tool, &input.context.trust_level),
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
        self.engine.check(&input.tool, &input.payload, &input.context.trust_level)
    }

    fn write_audit(&self, input: &GuardInput, decision: &GuardDecision) {
        let request_id = Uuid::new_v4().to_string();
        let include_hash = self.audit_cfg.include_payload_hash;
        let event = AuditEvent::from_decision(
            request_id,
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
            include_hash,
        );
        let line = event.to_jsonl();

        if self.audit_cfg.output == "file" {
            if let Some(ref mutex) = self.audit_file {
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

// ── Convenience: check_tool ──────────────────────────────────────────────────

impl Guard {
    pub fn check_tool(
        &self,
        tool: Tool,
        payload: impl Into<String>,
        context: Context,
    ) -> GuardDecision {
        let input = GuardInput {
            tool,
            payload: payload.into(),
            context,
        };
        self.check(&input)
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
        let decision = self.check(input);
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
        // Payload contract: {"command": "<shell command>"} for Tool::Bash.
        // This mirrors the validator's extraction and must never fall back to
        // bare-string matching — that would break the structured payload contract.
        let command = extract_bash_command(&input.payload)?;

        let mode = self.engine.effective_mode(&input.tool, &input.context.trust_level);
        let working_directory = input
            .context
            .working_directory
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let ctx = SandboxContext {
            mode,
            working_directory,
            timeout_ms: None, // callers may wrap with a context that sets this
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
