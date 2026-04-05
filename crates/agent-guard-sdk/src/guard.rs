use std::path::Path;

use agent_guard_core::{
    AuditConfig, AuditEvent, Context, DecisionCode, GuardDecision, GuardInput, PolicyEngine,
    Tool,
};
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
            let mode = trust_to_permission_mode(&input.context);
            let workspace_path: &Path = input
                .context
                .working_directory
                .as_deref()
                .unwrap_or_else(|| Path::new("."));
            let result = validate_bash_command(&input.payload, mode, workspace_path);
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
                if let Ok(mut file) = mutex.lock() {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", line);
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

fn trust_to_permission_mode(ctx: &Context) -> PermissionMode {
    use agent_guard_core::TrustLevel;
    match ctx.trust_level {
        TrustLevel::Untrusted => PermissionMode::ReadOnly,
        TrustLevel::Trusted => PermissionMode::WorkspaceWrite,
        TrustLevel::Admin => PermissionMode::DangerFullAccess,
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
