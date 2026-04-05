use agent_guard_core::{
    AuditConfig, AuditEvent, Context, GuardDecision, GuardInput, PolicyEngine, PolicyError, Tool,
};
use uuid::Uuid;

pub struct Guard {
    engine: PolicyEngine,
    audit_cfg: AuditConfig,
    // audit file writer is lazily opened on first use
    audit_file: Option<std::sync::Mutex<std::fs::File>>,
}

impl Guard {
    pub fn new(engine: PolicyEngine) -> Self {
        let audit_cfg = engine.audit_config().clone();
        let audit_file = if audit_cfg.output == "file" {
            if let Some(ref path) = audit_cfg.file_path {
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(f) => Some(std::sync::Mutex::new(f)),
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        Self {
            engine,
            audit_cfg,
            audit_file,
        }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        Ok(Self::new(PolicyEngine::from_yaml_str(yaml)?))
    }

    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, PolicyError> {
        Ok(Self::new(PolicyEngine::from_yaml_file(path)?))
    }

    /// Evaluate the guard decision for a tool call.
    /// Also emits an audit event if auditing is enabled.
    pub fn check(&self, input: &GuardInput) -> GuardDecision {
        let decision = self.engine.check(&input.tool, &input.payload, &input.context.trust_level);
        if self.audit_cfg.enabled {
            self.write_audit(input, &decision);
        }
        decision
    }

    fn write_audit(&self, input: &GuardInput, decision: &GuardDecision) {
        let request_id = Uuid::new_v4().to_string();
        let event = AuditEvent::from_decision(
            request_id,
            &input.tool,
            &input.payload,
            decision,
            input.context.session_id.clone(),
            input.context.agent_id.clone(),
            input.context.actor.clone(),
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
    /// Shorthand: construct a `GuardInput` and call `check`.
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
