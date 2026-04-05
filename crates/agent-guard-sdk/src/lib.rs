pub mod guard;

pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core directly.
pub use agent_guard_core::{
    AuditDecision, AuditEvent, Context, CustomToolId, DecisionCode, DecisionReason, GuardDecision,
    GuardInput, PolicyError, Tool, TrustLevel,
};

// Re-export sandbox types for execute() callers.
pub use agent_guard_sandbox::{SandboxContext, SandboxError, SandboxOutput};
