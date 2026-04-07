pub mod guard;
pub mod metrics;
pub use metrics::{get_metrics, Metrics};
pub mod anomaly;

pub use prometheus_client;
pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    Context, CustomToolId, DecisionCode, DecisionReason, GuardDecision, GuardInput, Tool,
    TrustLevel,
};

// Re-export sandbox types for direct usage
pub use agent_guard_sandbox::{Sandbox, SandboxContext, SandboxError, SandboxOutput};
