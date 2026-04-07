pub mod guard;
pub mod metrics;
pub mod anomaly;
pub use anomaly::{get_detector, AnomalyDetector, AnomalyStatus};

pub use metrics::{get_metrics, Metrics};
pub use prometheus_client;
pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    Context, CustomToolId, DecisionCode, DecisionReason, GuardDecision, GuardInput, Tool,
    TrustLevel,
};

// Re-export sandbox types for direct usage
pub use agent_guard_sandbox::{
    CapabilityDoctor, HealthStatus, Sandbox, SandboxCapabilities, SandboxContext, SandboxError,
    SandboxOutput, SandboxReport,
};
