pub mod guard;
pub mod metrics;
pub mod anomaly;

pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{
    Context, CustomToolId, DecisionCode, DecisionReason, GuardDecision, GuardInput, Tool,
    TrustLevel,
};

// Re-export sandbox traits and common implementations
pub use agent_guard_sandbox::{
    NoopSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};

#[cfg(target_os = "linux")]
pub use agent_guard_sandbox::SeccompSandbox;

#[cfg(feature = "macos-sandbox")]
pub use agent_guard_sandbox::SeatbeltSandbox;

#[cfg(feature = "windows-sandbox")]
pub use agent_guard_sandbox::JobObjectSandbox;
