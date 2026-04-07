pub mod guard;

pub use guard::{ExecuteOutcome, ExecuteResult, Guard, GuardInitError};

// Re-export core types so SDK users don't need to depend on agent-guard-core
pub use agent_guard_core::{Context, CustomToolId, GuardDecision, GuardInput, Tool, TrustLevel};

// Re-export sandbox traits and common implementations
pub use agent_guard_sandbox::{
    NoopSandbox, Sandbox, SandboxContext, SandboxError, SandboxOutput, SandboxResult,
};

#[cfg(target_os = "linux")]
pub use agent_guard_sandbox::SeccompSandbox;

#[cfg(feature = "macos-sandbox")]
pub use agent_guard_sandbox::SeatbeltSandbox;
