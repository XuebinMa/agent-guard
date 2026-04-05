pub mod guard;

pub use guard::Guard;

// Re-export core types so SDK users don't need to depend on agent-guard-core directly.
pub use agent_guard_core::{
    AuditDecision, AuditEvent, Context, CustomToolId, DecisionCode, DecisionReason, GuardDecision,
    GuardInput, PolicyError, Tool, TrustLevel,
};
