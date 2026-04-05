pub mod noop;

pub use noop::NoopSandbox;
use thiserror::Error;

pub type SandboxResult = Result<String, SandboxError>;

/// Abstraction over execution environments.
///
/// Platform support matrix (Phase 1):
/// - Linux: hard isolation via seccomp + namespaces — **planned** (Phase 2)
/// - macOS: `sandbox-exec` profiles — **experimental** (Phase 2)
/// - Windows: job object restrictions — **not yet implemented**
///
/// Current default is `NoopSandbox` (passthrough), which performs policy
/// enforcement but no OS-level isolation.
pub trait Sandbox: Send + Sync {
    fn name(&self) -> &'static str;
    fn execute(&self, command: &str, env: &[(&str, &str)]) -> SandboxResult;
    fn is_available(&self) -> bool;
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox not available on this platform: {0}")]
    NotAvailable(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("timeout after {seconds}s")]
    Timeout { seconds: u64 },
}
